# Privileged credential lifecycle monitoring

A Django application that collects account and lifecycle metadata from every
Privileged Access Management platform in the estate, normalizes it into one
schema, evaluates governance rules against it, and forwards the resulting
events and findings to the enterprise Security Information and Event
Management platform.

It answers the questions a credential estate cannot otherwise answer, because
each vault only knows about itself:

- How many privileged credentials exist across all four platforms, and how many
  are past their rotation interval right now?
- Which non-human credentials — service accounts, robotic process automation
  identities, application identities — have automatic rotation switched off, and
  when was it switched off, and by whom?
- Which privileged accounts have no accountable owner going into recertification?
- Which privileged accounts were discovered on target systems and never vaulted?
- Which platform stopped reporting, so that its silence is not mistaken for
  compliance?

## The one design constraint everything else follows from

**This system reads metadata about credentials. It never reads credential
values.** That is enforced in three independent places:

1. `connectors/base.py` ships a request session that raises
   `SecretRetrievalBlocked` on any path matching a known credential-retrieval
   endpoint across the supported vendors. Adding a call to
   `/Accounts/{id}/Password/Retrieve`, `/secrets/{id}/fields/password`,
   `/ManagedAccounts/{id}/Credentials`, or `/static-creds/{name}` fails at
   runtime rather than shipping.
2. `scrub()` walks every raw vendor payload and replaces value-bearing fields
   before persistence. `NormalizedAccount` runs it in `__post_init__`, so raw
   payloads cannot reach the database unscrubbed even through a new connector.
3. The vault-side service account should be granted list and audit rights only,
   without retrieval rights. The software control and the platform control are
   both required; neither is sufficient alone.

The consequence worth stating to your control owners: a compromise of this
dashboard yields a map of which privileged accounts exist and where governance
is weak. That is real reconnaissance value and the application is hardened
accordingly — but it yields no usable credential.

## Layout

```
access/         Developer and bot access: policy, approvals, reconciliation.
  workflow.py   Submission, segregation of duties, hashed decisions.
  reconcile.py  Platform reality against approved grants.
resources/      Read-only access enumeration per platform (GitHub, GitLab).
usage/          Where credentials were actually used.
  collectors.py Live feeds this system pulls itself, including TACACS+.
  ingest.py     Parsers for telemetry delivered as files.
  correlate.py  Joins vault retrievals to target logins; produces the residue.
connectors/     One adapter per vendor. Vendor vocabulary stops here.
  base.py       Contract, capability vocabulary, guards, scrubbing, parsing.
  registry.py   Plugin discovery, catalogue, credential-reference resolution.
  generic.py    Specification-driven connector. Onboard a tool with no code.
  contract.py   Conformance harness every new connector should pass.
  cyberark.py   Privileged Access Manager, Password Vault Web Access interface.
  delinea.py    Secret Server.
  beyondtrust.py Password Safe.
  vault.py      HashiCorp Vault static roles.
  specifications/ Worked mapping templates to copy.
inventory/      Normalized schema, admin, tests.
collection/     Reconciliation diff, Celery tasks.
rules/          Detection engine and the shipped rule set.
dashboard/      Operator console.
api/            Read interface for downstream consumers plus finding triage.
export/         Forwarder to the enterprise event collector.
```

Adding a platform means a mapping document, a connector class, or an installed
package — see below. No rule, view, or export path changes either way.

## Adding a new platform

There are three paths, and the right one depends on how far the tool's interface
sits from the common shape. Nothing outside `connectors/` changes in any of them
— no rule, view, serializer, or migration.

### 1. Specification only, no code

Most platforms expose a token endpoint, a paged account list, and an audit feed.
When yours does, describe it as a mapping document. Name the vendor in settings:

```python
PAM_SPECIFICATION_VENDORS = {"acme_vault": "Acme Vault"}
```

Then add a platform with that vendor and put the specification in its
`options`. `connectors/specifications/example-acme-vault.json` is a complete
worked template covering authentication styles, three pagination styles
(offset, page, cursor), dotted field paths with list indexes, value maps,
equality tests, and transforms (`iso_datetime`, `epoch`, `epoch_ms`, `int`,
`bool`, `not`, `seconds_to_days`).

Malformed specifications fail at construction with a message naming the
offending field, not silently at three in the morning mid-collection.

### 2. A connector class in this package

When the tool needs behaviour a document cannot express — per-account detail
fetches, request signing, a second call to resolve ownership — subclass
`PamConnector`, implement `authenticate` and `iter_accounts`, declare your
capabilities, and decorate:

```python
@register_connector
class AcmeConnector(PamConnector):
    vendor = "acme_vault"
    display_name = "Acme Vault"
    required_credentials = ("username", "password")
    capabilities = frozenset({Capability.ACCOUNTS, Capability.ROTATION_INTERVAL})
```

Dropping the module in `connectors/` is enough; discovery imports it. The vendor
dropdown in the configuration screen updates itself.

### 3. A separately distributed package

For a connector that cannot live in this repository or ships on its own
cadence, publish a package exposing the `pamsiem.connectors` entry point:

```toml
[project.entry-points."pamsiem.connectors"]
acme_vault = "acme_pam_connector:AcmeConnector"
```

Installing it registers the connector. A connector that fails to import is
logged and skipped rather than taking the application down with it.

### Before you enable it

```bash
python manage.py list_connectors                     # catalogue and capabilities
python manage.py validate_connector "Acme - prod"    # dry run, writes nothing
```

`validate_connector` authenticates, pulls a sample, and prints per-field
coverage plus the classification spread. This catches the two failures that
otherwise reach production looking healthy: pagination that silently truncates,
and an account list that comes back full while every lifecycle field is empty
because the mapping points at the wrong path. A field at zero percent means
either the platform does not expose it or your mapping is wrong — both need
resolving before the numbers mean anything.

Then mix `ConnectorContractTests` from `connectors/contract.py` into a test case
with a folder of recorded responses. It checks pagination completeness,
identifier stability and uniqueness, timezone-aware timestamps, capability
declaration, and that no credential value survives into a stored payload.

## Which systems a credential was actually used on

A vault records **retrieval**. It does not record **use**. Once a credential
leaves the vault, the vault is blind — so "who checked it out" and "what it was
used on" are different questions, and only the first has an easy answer.

Three tiers close the gap, in descending order of certainty:

| Tier | Source | Certainty | Sees |
|---|---|---|---|
| 1 | Sessions the vault brokered (session proxy) | Fact — the vault mediated it | Exact target, duration, often the commands |
| 2 | Credential fetches by named applications | Fact | Which application, and the host it ran on |
| 3 | Target-side authentication telemetry, correlated back | Inference | Direct connections the vault never brokered |

Tiers one and two arrive through the connector's `iter_usage`, implemented for
CyberArk's session recordings and Password Safe's sessions. Tier three arrives
through `usage/ingest.py` from the systems being logged in to — Cisco TACACS+
accounting from Identity Services Engine (the richest feed for a network estate:
device, account, privilege level, and every command), Windows 4624 and 4625,
Unix authentication and privilege escalation, and database audit. Those are
files exported by the enterprise event platform, so the collector does no
network work for them and holds no credentials for them.

```bash
python manage.py ingest_usage --source "Cisco Identity Services Engine" --file /feeds/tacacs.log
python manage.py ingest_usage --all      # every enabled feed
python manage.py correlate_usage         # correlation on its own
```

### TACACS+ specifically

On a network estate this is the richest evidence of credential use there is: the
device, the account, the privilege level obtained, and every command entered,
per session. Nothing a vault produces comes close, because the vault only knows
the credential was handed out.

Three routes, in descending order of fidelity, all yielding the same record
shape:

| Collector | Route | Back-fills | Trade-off |
|---|---|---|---|
| `ise_data_connect` | Read-only database view on Identity Services Engine 3.2+ | Yes | Needs the `oracledb` package and Data Connect enabled |
| `syslog_spool` | Rotating files a syslog collector already writes | No | Sees nothing before forwarding was switched on |
| `tacplus_log` | tac_plus daemon accounting file | From file start | For estates not running Identity Services Engine |

Configure one under Configuration → telemetry sources: pick the collector, fill
in `settings` (host, view name, or path glob), and point `credential_reference`
at something like `env:ISE_DATA_CONNECT`. As with vault credentials, the
database holds a pointer and never the credential itself.

Data Connect is the one to reach for when you want a **utilisation baseline**
rather than to start accumulating one — ask it for a month and you get a month.
Syslog only ever tells you about the present. Both roll the per-command
accounting rows into one session, so a twenty-command change is one login rather
than twenty.

The cursor advances only after records are stored, so a failure mid-pull re-reads
its window rather than silently skipping it. The syslog collector tracks a byte
offset per file and re-reads from the start when a file shrinks, which is what
rotation looks like from the outside.

Two caveats. Data Connect view and column names have moved between Identity
Services Engine releases; the defaults target 3.2 and both are overridable in
`settings` so an upgrade is a configuration change rather than a code one.
Confirm them against your own release before trusting the numbers. And command
accounting is only as complete as the device configuration — a device sending
authentication records but not command accounting will show the login and none
of the commands, which looks like a quiet session rather than a gap.

### The residue is the point

Correlation matches each target login to a vault retrieval within a window. The
matches are not interesting. The two residues are:

- **A login with no retrieval behind it.** A managed privileged credential
  authenticated somewhere, and no checkout accounts for it. The plain reading is
  that a working copy exists outside the vault — in a script, a runbook, a saved
  session, someone's password manager. **This is the finding no vault can produce
  on its own**, because the vault genuinely did not see the event. Rule USE-004,
  critical.
- **A retrieval with no login behind it.** Usually benign — a check that failed,
  a change called off. Occasionally it is a credential being collected rather
  than used. Rule USE-006, medium, deliberately.

Plus the reach question: `CredentialAssetLink` rolls up which assets each
credential has been seen on, so blast radius is one indexed read. That number
decides two things at once — how far a compromise of one credential travels, and
how many systems a rotation touches. The second is why the first never gets
fixed. Rules USE-005 (used beyond its mapped target) and USE-007 (opens an
unusually large number of systems) work off it.

### Attribution rules, and why they are conservative

Correlation is inference, not proof. Clock skew, batched log delivery, and shared
service accounts all produce false pairings, and a false match hides the finding
that matters most. So:

- One retrieval may explain at most one login. A burst from a single checkout
  leaves the rest unexplained rather than all of them inheriting one
  justification.
- Where both sides name a person, they must be the same person.
- An account mapped to the exact asset wins over a same-named account elsewhere,
  and an ambiguous name is left unattributed rather than attributed wrongly —
  domain administrator names repeat across an estate.
- Four-hour forward window, five-minute backward tolerance for skew and for
  session-start records that beat their checkout record.
- Every observation keeps the lag that produced its match, so a reviewer can
  judge it.

Names are normalised across targets, so `CORP\svc_batch`, `svc_batch@corp.local`
and `svc_batch` resolve to one managed account. Accounts appearing in target logs
and in no vault are surfaced separately — those are privileged logins happening
entirely outside the vaults.

The **Usage** page carries all of this: blast radius, the mechanism split, the
unexplained feed, unmanaged accounts seen on targets, and which assets the most
credentials reach. Account detail gains a "where this credential has been used"
panel with off-scope assets marked.

## Developer and bot access approval

Requests, policy, approvals, handoff, then reconciliation against what the
platforms actually report.

**This system records approvals; it does not grant access.** Provisioning is
handed to whatever already owns it — the source control platform, the identity
governance suite, a change ticket. Three reasons, worth being able to recite in
a design review:

1. A monitoring system that can also grant is a monitoring system whose
   compromise grants. Everything else here is read-only by construction, and
   that property is worth more than a provision button.
2. The platforms already have provisioning, with their own controls and audit.
   Duplicating it creates two sources of truth about who has access, and the
   disagreement surfaces during an incident.
3. What is missing in most estates is not a provisioning mechanism. It is the
   record of *why* someone has access, whether it was ever approved, and whether
   it was removed when it was supposed to be.

### The screens

| Path | What it does |
|---|---|
| `/access/` | Estate view: unapproved access, expired-but-live, standing production access |
| `/access/queue/` | What you can decide, what you cannot and why, what you raised |
| `/access/request/` | Raise a request, with the applicable policy shown before you submit |
| `/access/requests/<reference>/` | The record: request, hashed approval chain, decide, hand off, revoke |

The queue splits into "you can decide these" and "pending, but not yours to
decide" with the reason against each. Hiding the second list would make the
separation invisible; showing it makes the rule obvious rather than surprising,
and stops an approver emailing someone to ask why a request vanished.

The request form shows the ceiling and approval count for each production
resource before submission. A requester who learns the ceiling by having a
request refused asks for the maximum every time afterwards.

Views never decide anything themselves. They call the workflow and render its
refusal, so a request raised through a screen, a management command, or a future
service desk integration passes through identical gates. Decisions are POST
only, carry a cross-site request forgery token, and record the source address.

### What is enforced, not reported

Enforced at the point of decision, because a control that raises a finding after
production write access was self-approved has prevented nothing:

- The requester cannot approve their own request, and nobody can approve access
  for themselves.
- The same approver cannot count twice toward a two-approval requirement.
- An approver outside the policy's entitled groups is refused.
- An approver marked independent cannot approve for their own team.
- Durations are capped at submission against the policy ceiling. Standing access
  is refused unless the policy explicitly allows it.
- A non-human principal with no responsible human named cannot hold access at
  all.

Policies match most specific first — a policy naming the resource beats one
naming the platform, which beats the catch-all — and ties break toward the
stricter policy, so a configuration mistake fails closed.

### Tamper-evident approvals

Each approval is hashed over its own content and the previous record's hash. A
decision edited afterwards breaks every link after it, and `verify_chain` says
which. An approval record that can be quietly edited is not evidence of
anything.

```bash
python manage.py verify_approvals
```

Rule ACC-008 runs the same check on every request. If it fires, the approval
evidence for that request cannot be relied on, and it is an incident rather than
a data quality issue.

### Reconciliation is what makes the workflow worth having

Read-only connectors enumerate GitHub and GitLab: direct collaborators, teams,
deploy keys, deploy tokens, and inherited group membership. The connectors
refuse paths that return source or secrets before the request is made, so this
cannot become a code-reading or secret-reading path.

```bash
python manage.py reconcile_access --platform github --organisation acme-bank
python manage.py reconcile_access --platform gitlab --group platform
```

Diffing the platform against the grant table produces the two answers an
examiner actually wants:

- **Access with no approval behind it** (ACC-001). The access is real; the
  authority for it is recorded nowhere. Most will turn out legitimate and
  undocumented, which is a different problem from being wrong. Without
  reconciliation, a request form only proves that the people who used it
  followed the process.
- **Access that expired on paper and not in reality** (ACC-002). Worse than
  having no expiry, because the register says the access is gone.

Deploy keys and deploy tokens are enumerated deliberately: they are repository
write access with no person attached, and a recertification campaign aimed at
people never sees them.

### The cross-domain rule

ACC-006 is the argument for keeping access and credential lifecycle in one
system. A bot with production write access is normal. A credential that has not
rotated in six months is a housekeeping item. Together they are a durable,
unmonitored path into production that nobody is looking at, because the access
sits in one team's register and the credential in another's. Principals are
joined to vaulted credentials on stated identifiers only — a guessed link would
put a rotation finding on the wrong bot.

| Identifier | Severity | Condition |
|---|---|---|
| ACC-001 | high, critical on production | Access held with no approved request behind it |
| ACC-002 | critical | Access past its expiry still live on the platform |
| ACC-003 | high | Non-human identity with elevated access and no responsible human |
| ACC-004 | critical | Approved by someone who should not have approved it |
| ACC-005 | high | Standing elevated access on a production resource |
| ACC-006 | critical | Bot writes to production with a credential that is not rotating |
| ACC-007 | medium | Access granted and never used |
| ACC-008 | critical | An approval record has been altered after the fact |

## Capabilities: why an unsupported rule is not a clean rule

Platforms differ in what they can tell you. HashiCorp Vault static roles carry
no owner attribute; Secret Server has no audit feed unless you configure a
report identifier. A rule that cannot run produces exactly the same empty result
as a rule that ran and found nothing, and treating those as the same thing is
how a blind spot gets signed off as compliance.

So each connector declares what it supplies, each rule declares what it needs,
and the engine skips the combinations that cannot work — reporting them as
`unsupported_rules` rather than as zero findings. The **Coverage** page renders
the full rule-against-platform matrix: live cells show the open count, inert
cells are hatched and name the missing input. Open it before telling anyone the
estate is clean.

Capabilities are cached on the platform row at each successful collection, so
the rule engine and the coverage view never need credentials. A deployment can
subtract one it has not enabled through `options["disabled_capabilities"]`.

One deliberate asymmetry: losing a capability does not resolve findings the rule
already raised. Switching off an audit feed should not quietly close every
break-glass finding it produced.

## Data model, in one paragraph

`PamSystem` is a platform to collect from. `ManagedAccount` is the current
known state of one privileged credential. `AccountSnapshot` is a per-run copy
of the lifecycle fields, which is what makes historical posture reporting
possible. `LifecycleEvent` is the event stream — derived transitions from the
reconciliation diff, plus ingested vendor audit records. `Finding` is a stateful
policy violation with an open and resolve lifecycle. `RuleConfiguration` is
per-deployment tuning. `DiscoveredAccount` holds privileged accounts found on
target systems, so the gap against `ManagedAccount` is measurable.

## The reconciliation diff is where the value is

A vault tells you what is true now. It rarely tells you what changed.
`collection/reconcile.py` compares each pull against stored state and emits
lifecycle events for rotation, rotation failure, ownership change, status
change, verification failure, and automatic rotation being toggled. That diff is
what produces *"automatic rotation on this robotic process account was disabled
on Tuesday and never re-enabled"* — the finding an examiner actually asks for,
and the one no single vault interface reports.

One guard rail is worth knowing about: if a pull returns fewer than half the
accounts already known for that platform, the reconciler refuses to retire
anything and logs an error. A vendor outage returning a short page would
otherwise generate a catastrophic false "everything was deleted" event storm.

## Rules shipped

| Identifier | Severity | Condition |
|---|---|---|
| ROT-001 | high, critical past twice the interval | Rotation past its policy interval |
| ROT-002 | critical | Automatic rotation failing repeatedly |
| ROT-003 | high | Vault copy no longer matches the target system |
| BOT-001 | high | Non-human account with automatic rotation switched off |
| BOT-002 | critical | Non-human credential never rotated |
| BOT-003 | high | Automatic rotation disabled on a non-human account recently |
| OWN-001 | medium, high for non-human | No recorded owner |
| OWN-002 | high | Recorded owner is no longer an active identity |
| USE-001 | medium | Active privileged account dormant past the threshold |
| USE-002 | critical | Break-glass credential retrieved with no ticket reference |
| USE-003 | high | Retrieval volume far above the account's own baseline |
| USE-004 | critical | Privileged login with no vault retrieval behind it |
| USE-005 | high | Credential used on assets beyond the one it is mapped to |
| USE-006 | medium | Credential retrieved and never used |
| USE-007 | high | One credential opens an unusually large number of systems |
| ONB-001 | high | Privileged account discovered on a target but not vaulted |
| SOD-001 | medium | Shared human account without exclusive checkout |
| DEL-001 | low | Sat in pending deletion past the grace window |
| OPS-001 | high | Collection from a platform has stopped |
| OPS-002 | high | A target telemetry feed has stopped |

Each rule declares the platform capabilities it needs, so it runs only where
those inputs exist. Findings are stateful. A condition holding for six weeks is one finding aged six
weeks, not forty-two alerts. Suppression is time-boxed to a maximum of 180 days
on purpose — an indefinite exception is how a rotation gap survives three audit
cycles.

Every threshold lives in `RuleConfiguration.parameters` and every rule supports
container and account exemptions, so tuning is a configuration change with an
audit trail rather than a code deployment.

## Account classification drives most of the rule set

The split between human and non-human decides which rules apply, and no vendor
reports it reliably. Classification is therefore configurable rather than
hard-coded: set `kind_patterns` in `PAM_CONNECTOR_DEFAULTS` or per platform in
`PamSystem.options` as ordered `[regular expression, kind]` pairs matched
against `container/platform/username`. First match wins, and a built-in fallback
catches common naming conventions.

Expect to spend real time on this against your actual naming standards. An
account classified `unknown` is invisible to the non-human rules, so track the
`unknown` count on the population panel as a data quality measure.

## Running it

### Local, in five minutes, with nothing else installed

No database server, no broker, no vault. SQLite and a synthetic estate.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export DJANGO_SECRET_KEY=$(python -c "from django.core.management.utils import get_random_secret_key as g; print(g())")
export DJANGO_DEBUG=true
export USE_SQLITE=1

python manage.py demo             # migrate, seed, create a login, verify
python manage.py runserver        # in this same shell
```

`demo` does everything in one process and prints the absolute path of the
database it used, the row counts it verified, and the login it created. It
refuses to run outside a debug build against a non-SQLite database, because it
fabricates an estate and resets a password.

**Run `runserver` in the same shell.** The one failure that keeps recurring and
produces no error is seeding in one terminal and serving from another with
different environment variables: two different databases, everything appears to
have worked, and the dashboard is empty. `python manage.py doctor` in the
server's shell settles it.

If the dashboard looks empty, run `python manage.py doctor` **in the same shell
as the server**. It prints which database that process is actually talking to,
whether the file exists, and what is in it. The usual answer is that the shell
that seeded and the shell running the server had different environment variables,
so they were writing to and reading from two different databases.

Open <http://127.0.0.1:8000/>, sign in at the admin prompt, and you land on the
posture page. Coverage, Accounts, and Findings are in the masthead.

`seed_demo` evaluates the rules for you and prints a walkthrough: seven planted
situations with the account name and the story behind each, then a suggested
order to show them in. It generates a plausible background population and plants
those specific cases on top, because a demonstration where every row looks alike
proves nothing — nobody can tell whether the tool found something or the data was
arranged to look busy. `--accounts 4000` for a heavier estate, `--reset` to start
clean, `--seed` to change the arrangement.

The estate deliberately includes a platform that is stale and failing
authentication, so the coverage page has something to say. It also includes a
specification-driven platform with a narrower feed, so the coverage matrix shows
real differences between platforms rather than a uniform grid.

### Against real platforms

```bash
cp .env.example .env              # fill it in
set -a && source .env && set +a

python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

Add each platform under Configuration, then, before enabling it:

```bash
python manage.py list_connectors                  # what is registered
python manage.py validate_connector "Vault - corporate"   # dry run, writes nothing
python manage.py collect "Vault - corporate" --evaluate   # one real pass
```

`collect` and `evaluate_rules` run the same code as the scheduled tasks, in the
foreground, so you can onboard a platform before standing up a broker.

### Scheduled

Once collection is proven, hand it to the workers:

```bash
celery -A pamsiem worker --loglevel=info
celery -A pamsiem beat   --loglevel=info
```

Production wants PostgreSQL (drop `USE_SQLITE`), `DJANGO_DEBUG=false`, a real
`DJANGO_ALLOWED_HOSTS`, `PAM_CA_BUNDLE` pointing at the enterprise certificate
bundle, and gunicorn behind your load balancer rather than `runserver`.

Schedule, in `pamsiem/celery.py`: collection every fifteen minutes with each
platform respecting its own interval, rule evaluation hourly and immediately
after each successful collection, forwarding every five minutes, history pruning
nightly.

The `credential_reference` field on each platform holds a pointer such as
`env:PAM_CYBERARK_PROD` or `file:/run/secrets/cyberark.json`, never a
credential.

## Vault-side permissions to request

| Platform | Grant | Explicitly withhold |
|---|---|---|
| CyberArk Privileged Access Manager | List Accounts on every in-scope safe, View Audit | Retrieve Accounts, Use Accounts |
| Delinea Secret Server | View Secret, View Audit | Retrieve Secret, View Launcher Password |
| BeyondTrust Password Safe | Managed account read, Managed system read, audit read | Credential request and checkout |
| HashiCorp Vault | Read and list on `<mount>/static-roles/*` | Read on `<mount>/static-creds/*` |

## Caveats, stated plainly

- **Endpoint shapes are version-dependent.** The connectors target the 12.x/13.x
  generation of CyberArk, current Secret Server and Password Safe, and Vault 1.1x.
  Field names have moved between releases. Validate each mapping against your own
  environment's interface documentation before trusting a number, and change the
  mapping rather than the parsing logic.
- **Rotation interval discovery is imperfect.** CyberArk carries it on the
  platform policy rather than the account, so `_interval_days` reads a short list
  of common property names and falls back to `default_rotation_interval_days`.
  An account inheriting a 30-day policy that the collector reads as the 90-day
  fallback will look compliant for two months longer than it is. Verify the
  interval column against a sample of platform policies during onboarding.
- **CyberArk activity collection walks accounts one at a time.** It is expensive
  on a large vault. Restrict it with `activity_containers` to the safes that
  matter for detections, or feed the vault's own syslog stream into the event
  collector instead and treat this application as the inventory and posture
  layer only.
- **USE-002 and USE-003 need an activity feed.** Without one, `LifecycleEvent`
  contains only derived transitions and both rules stay silent — which looks
  identical to clean. Confirm activity ingestion before reporting on them.
- **OWN-002 needs an identity feed.** Load the active-worker list into the cache
  key `active_identities` from your identity governance platform. Without it the
  rule is inert by design rather than noisy.
- **ONB-001 attaches its finding to an anchor account on the same target**, so
  several unvaulted accounts on one host currently collapse into a single
  finding whose evidence reflects the most recent one. If unvaulted-account
  reporting is a primary use case, give `DiscoveredAccount` its own finding
  target rather than reusing `ManagedAccount`.
- **The declarative connector covers the common shape, not every shape.** It
  handles token and basic authentication, three pagination styles, and flat field
  mapping. It does not do request signing, per-account detail fetches, or
  cross-referencing a second endpoint. When you find yourself adding transforms
  to make it fit, write the subclass instead — a specification that needs
  bespoke transforms is a class wearing a disguise.
- **Capabilities are self-declared.** A connector claiming to supply usage
  timestamps while returning them empty will keep its rules live and produce
  nothing, which is the failure mode capabilities were meant to remove. Run
  `validate_connector` and check the field coverage against the declared
  capabilities before enabling collection.
- **Correlation produces false pairings, in both directions.** A login attributed
  to the wrong retrieval hides a USE-004 finding; one left unattributed raises a
  false alarm. Batched log delivery is the usual cause — a feed that arrives
  hourly in bulk will push logins outside the window. Tune `--window-hours`
  against your own delivery latency before treating the unexplained count as a
  number rather than a queue, and note that the count is a starting point for
  investigation, not a conclusion.
- **Shared service accounts weaken attribution further.** Where several people
  can check out the same credential and neither side names an individual, the
  pairing rests on timing alone. Exclusive checkout and per-person accounts are
  what make this tier trustworthy; SOD-001 exists partly to push in that
  direction.
- **Tier three coverage is only as wide as the feeds.** Devices that do not send
  accounting records, hosts outside event forwarding, and databases without audit
  enabled are invisible, and their silence looks exactly like clean. OPS-002 and
  the Usage page's feed table are the guard against that.
- **Approval enforcement only covers what goes through the workflow.** Access
  added directly on the platform bypasses every check in this module — which is
  exactly why reconciliation exists, and why ACC-001 will be the largest finding
  population on day one. Treat that first number as a backlog to document, not a
  list of things to revoke.
- **Bot-to-credential linking is conservative and therefore incomplete.** Only
  unambiguous name matches are joined, so ACC-006 under-reports rather than
  attributing a rotation finding to the wrong bot. Link the rest by hand in the
  configuration screen.
- **The risk score is for sorting only.** It is a blend with no external
  validation. Every decision should trace to a named rule with named evidence,
  which is why the score appears in a sort column and nowhere in a control.
- **Retention defaults are placeholders.** Snapshots at 400 days and events at
  730 days were chosen to survive an annual audit cycle plus a quarter. Replace
  them with whatever your records retention schedule actually requires before
  production.

## Storage

Yes, it needs a database, and not incidentally. The stored history is the
product: the reconciliation diff that turns "what is true now" into "what
changed" only works against a previous pull, findings are stateful so a
condition holding for six weeks is one aged finding rather than forty-two
alerts, and correlation joins retrievals to logins across time. Run this
stateless and it degrades into a log shipper.

Locally, SQLite ships with Python — nothing to install. For anything real,
PostgreSQL: Celery workers write concurrently, and the JSON columns and partial
indexes matter at size.

Rough sizing for a ten thousand account estate, collected every thirty minutes:

| Table | Growth | Note |
|---|---|---|
| `ManagedAccount` | ~20 MB, flat | One row per credential, scrubbed vendor payload included |
| `AccountSnapshot` | ~1 GB a year | Written on change plus one heartbeat per account per day |
| `LifecycleEvent` | ~500 MB a year | Rotations, failures, ownership changes, retrievals |
| `UsageObservation` | **the driver** | One row per privileged login across the estate |

`UsageObservation` is the one to plan for. A large Windows estate can produce
hundreds of thousands of privileged logon events a day before filtering, so:
restrict each feed at export time to the account names that are actually
managed, keep `USAGE_RETENTION_DAYS` short (120 by default), and lean on the
fact that the durable value is already rolled up into `CredentialAssetLink` and
forwarded downstream. Consider monthly partitioning on `occurred_at` if you keep
more than a quarter.

`AccountSnapshot` had the same problem and no longer does. A row per account per
run is the obvious implementation and does not survive a real estate — ten
thousand accounts every half hour is half a million near-identical rows a day.
Snapshots are now written when something changed, plus one heartbeat per account
per `SNAPSHOT_MIN_INTERVAL_HOURS`, which gives the same posture history at a
fraction of the volume.

Redis is needed in production for the Celery broker and for the shared cache the
identity feed uses. Neither is needed for the local demonstration: SQLite plus a
file-backed cache, and the foreground `collect`, `evaluate_rules`, and
`ingest_usage` commands cover everything the workers would do.

## Tests

```bash
python manage.py test connectors inventory
```

Coverage concentrates on the four places a defect would be expensive: the
metadata-only guards, the reconciliation diff, the mass-retirement guard rail,
and the extension surface — registry conflicts, specification validation,
pagination completeness, and capability gating. A wrong dashboard number is embarrassing; a leaked credential value or a
false purge event storm is an incident.
# QuantlyxSiem
# QuantlyxSiem
# QuantlyxSiem
