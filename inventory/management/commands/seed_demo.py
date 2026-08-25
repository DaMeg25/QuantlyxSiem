"""
Build a synthetic estate that behaves like a real one.

Contacts nothing. Every account, event, and finding here is generated locally.

The point is not volume. A demonstration fails when every rule fires on
identical-looking rows, because nobody can tell whether the tool found something
or the data was arranged to make it look busy. So this generates a plausible
background population and then plants a small number of specific, narratable
situations on top -- the robotic process account whose rotation was switched off
during an outage and never restored, the break-glass credential pulled five
times with no change ticket, the owner who left in March. Those are the ones to
walk someone through; the background is what makes them credible.

    python manage.py seed_demo                  # ~1,200 accounts, five platforms
    python manage.py seed_demo --accounts 4000  # heavier
    python manage.py seed_demo --reset          # wipe previous demo data first
"""

from __future__ import annotations

import random
import textwrap
from datetime import timedelta

from django.core.cache import cache
from django.core.management import call_command
from django.db import transaction
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from connectors.registry import get_connector_class
from inventory.models import (
    AccountKind,
    AssetType,
    AccountSnapshot,
    AccountStatus,
    CollectionRun,
    DiscoveredAccount,
    Finding,
    LifecycleEvent,
    ManagedAccount,
    PamSystem,
    RuleConfiguration,
    TargetAsset,
    TelemetrySource,
    UsageObservation,
)

# --------------------------------------------------------------------------
# Estate shape
# --------------------------------------------------------------------------

PLATFORMS = [
    # name, vendor, base url, share of estate, interval minutes, health
    ("Vault - corporate", "cyberark", "https://pvwa.corp.example.com", 0.42, 30, "healthy"),
    ("Secret Server - payments", "delinea", "https://secretserver.pay.example.com", 0.24, 60, "healthy"),
    ("Password Safe - infrastructure", "beyondtrust", "https://passwordsafe.corp.example.com", 0.20, 60, "healthy"),
    ("Vault - platform engineering", "hashicorp_vault", "https://vault.plat.example.com", 0.10, 15, "healthy"),
    ("Acme Vault - treasury", "acme_vault_demo", "https://acme.treasury.example.com", 0.04, 60, "stale"),
]

SAFES = {
    "cyberark": ["WIN-DOMAIN-ADMIN", "UNIX-ROOT", "NETWORK-DEVICES", "DB-ORACLE",
                 "RPA-BATCH", "BREAKGLASS", "VENDOR-ACCESS"],
    "delinea": ["Payments\\Production", "Payments\\Non-production",
                "Settlement\\Batch", "Treasury\\Interfaces"],
    "beyondtrust": ["corp.example.com", "dmz.example.com", "esx-cluster-a", "aci-fabric"],
    "hashicorp_vault": ["database", "ad", "aws"],
    "acme_vault_demo": ["TREASURY-CORE", "SWIFT-GATEWAY"],
}

HOSTS = [
    "nyc-dc01.corp", "nyc-dc02.corp", "chi-dc01.corp", "core-rtr-01", "core-rtr-02",
    "edge-fw-01", "aci-apic-01", "f5-ltm-04", "f5-ltm-05", "oradb-prod-03",
    "oradb-prod-04", "pgsql-pay-01", "esx-cluster-a", "esx-cluster-b", "swift-gw-01",
    "batch-rpa-01", "batch-rpa-02", "jump-nyc-01", "vcenter-01", "netscaler-02",
]

APPLICATIONS = [
    "Payments hub", "Settlement engine", "Branch network", "Data warehouse",
    "Trade capture", "Treasury workstation", "SWIFT gateway", "Card authorisation",
    "Regulatory reporting", "Collateral management",
]

TEAMS = [
    "Network engineering", "Payments platform", "Database engineering",
    "Infrastructure operations", "Treasury technology", "Identity and access",
]

SURNAMES = [
    "chen", "okafor", "delgado", "novak", "haddad", "iyer", "kowalski", "moreau",
    "silva", "tanaka", "abbas", "lindqvist", "rossi", "mwangi", "petrov", "nguyen",
]
INITIALS = "abcdehjklmnprstv"

# Owners who have left, deliberately still attached to live accounts. This is
# the gap OWN-002 exists to find, and it is invisible to a recertification that
# only checks whether the owner field is populated.
DEPARTED = ["m.petrov@example.com", "s.kowalski@example.com", "d.rossi@example.com"]

# People named in the planted scenarios below. Present in the active-worker feed.
SCENARIO_OWNERS = [
    "a.iyer@example.com", "j.novak@example.com", "l.haddad@example.com",
    "t.delgado@example.com", "r.chen@example.com", "b.mwangi@example.com",
    "p.tanaka@example.com", "k.lindqvist@example.com", "e.silva@example.com",
]

KIND_WEIGHTS = [
    (AccountKind.SERVICE, 34),
    (AccountKind.HUMAN, 30),
    (AccountKind.APPLICATION, 14),
    (AccountKind.BOT, 12),
    (AccountKind.VENDOR, 4),
    (AccountKind.UNKNOWN, 4),
    (AccountKind.BREAK_GLASS, 2),
]

PREFIX = {
    AccountKind.HUMAN: "adm",
    AccountKind.SERVICE: "svc",
    AccountKind.BOT: "rpa",
    AccountKind.APPLICATION: "app",
    AccountKind.BREAK_GLASS: "firecall",
    AccountKind.VENDOR: "vendor",
    AccountKind.UNKNOWN: "gen",
}

ACTOR_ADDRESSES = ["10.20.30.44", "10.20.31.9", "10.44.2.17", "172.18.4.61", "10.20.30.115"]

KIND_POPULATION = [value for value, weight in KIND_WEIGHTS for _ in range(weight)]


class Command(BaseCommand):
    help = "Generate a synthetic estate with planted scenarios. Contacts nothing."

    def add_arguments(self, parser):
        parser.add_argument("--accounts", type=int, default=1200)
        parser.add_argument("--reset", action="store_true", help="Delete existing data first")
        parser.add_argument("--seed", type=int, default=20260812)
        parser.add_argument("--no-evaluate", action="store_true", help="Skip the rule run")

    def handle(self, *args, **options):
        self.random = random.Random(options["seed"])
        self.now = timezone.now()
        self.scenarios: list[tuple[str, str, str]] = []

        existing = ManagedAccount.objects.count()
        if existing and not options["reset"]:
            # Running this twice used to fail halfway through on a unique
            # constraint, leaving a half-written estate that looked like the
            # command had worked. Refuse plainly instead.
            raise CommandError(
                f"This database already holds {existing} accounts. Re-running would collide "
                "with them. Use 'python manage.py seed_demo --reset' to replace the estate, "
                "or point at an empty database."
            )

        if options["reset"]:
            self.stdout.write("Clearing existing data ...")
            from access.models import (AccessGrant, AccessRequest, ApprovalPolicy,
                                       Approver, Principal, Resource)
            for model in (AccessGrant, AccessRequest, ApprovalPolicy, Approver, Principal,
                          Resource, Finding, UsageObservation, LifecycleEvent, AccountSnapshot,
                          CollectionRun, ManagedAccount, TargetAsset, TelemetrySource,
                          DiscoveredAccount, PamSystem, RuleConfiguration):
                model.objects.all().delete()

        with transaction.atomic():
            systems = self._platforms()
            self._owners()
            accounts = self._accounts(systems, options["accounts"])
            self._scenarios(systems)
            self._events(accounts)
            self._snapshots(accounts)
            self._runs(systems)
            self._discovered()
            self._usage(accounts)
            self._access(accounts)

        self.stdout.write(
            self.style.SUCCESS(
                f"\n{ManagedAccount.objects.count()} accounts across {len(systems)} platforms, "
                f"{LifecycleEvent.objects.count()} lifecycle events, "
                f"{AccountSnapshot.objects.count()} snapshots, "
                f"{DiscoveredAccount.objects.count()} unvaulted discoveries"
            )
        )

        if not options["no_evaluate"]:
            self.stdout.write("\nEvaluating rules ...")
            call_command("evaluate_rules")
            self._triage()

        self._walkthrough()

    # ---- platforms -----------------------------------------------------

    def _platforms(self) -> list[PamSystem]:
        systems = []
        for name, vendor, url, _share, interval, health in PLATFORMS:
            system, _ = PamSystem.objects.get_or_create(
                name=name,
                defaults={"vendor": vendor, "base_url": url,
                          "credential_reference": f"env:PAM_{vendor.upper()}_DEMO"},
            )
            system.vendor = vendor
            system.base_url = url
            system.collection_interval_minutes = interval
            system.enabled = True
            # One platform is deliberately stale: every detection for it has
            # stopped, which reads identically to compliance until OPS-001 and
            # the coverage page say otherwise.
            system.last_successful_collection = (
                self.now - timedelta(days=4) if health == "stale"
                else self.now - timedelta(minutes=self.random.randint(2, 20))
            )
            try:
                system.capabilities = sorted(get_connector_class(vendor).capabilities)
            except Exception:
                system.capabilities = ["accounts", "rotation_interval"]
            if vendor == "acme_vault_demo":
                # A specification-driven platform with a narrower feed, so the
                # coverage matrix shows real differences rather than a uniform grid.
                system.capabilities = ["accounts", "ownership", "rotation_interval"]
                system.options = {"spec": {"note": "demonstration only, never contacted"}}
            system.save()
            systems.append(system)
        return systems

    def _owners(self) -> None:
        self.owner_pool = [
            f"{self.random.choice(INITIALS)}.{surname}@example.com" for surname in SURNAMES
        ]
        # Owners named in the planted scenarios must be recognisable as current
        # staff, or OWN-002 fires on all of them and drowns the story it is
        # meant to tell.
        self.owner_pool.extend(SCENARIO_OWNERS)
        # The active-worker feed OWN-002 joins against. Departed owners are absent
        # from it, and are never handed out to the background population -- a
        # realistic estate has a handful of these, not a third of the accounts.
        cache.set("active_identities", sorted(set(self.owner_pool) - set(DEPARTED)), 86400)

    # ---- background population ----------------------------------------

    def _accounts(self, systems, total: int) -> list[ManagedAccount]:
        rng = self.random
        rows = []
        index = 0
        for system, (_name, vendor, _url, share, _interval, _health) in zip(systems, PLATFORMS):
            count = max(8, int(total * share))
            safes = SAFES[vendor]
            for _ in range(count):
                index += 1
                kind = rng.choice(KIND_POPULATION)
                team = rng.choice(TEAMS)
                username = f"{PREFIX[kind]}_{team.split()[0].lower()}{index:04d}"
                interval = rng.choice([30, 30, 60, 90, 90, 90, 180])

                # Age distribution: mostly healthy with a long tail out of policy,
                # so the histogram has a shape instead of a flat block.
                bucket = rng.random()
                if bucket < 0.60:
                    age = rng.randint(0, int(interval * 0.7))
                elif bucket < 0.82:
                    age = rng.randint(int(interval * 0.7), interval)
                elif bucket < 0.95:
                    age = rng.randint(interval, int(interval * 2.2))
                else:
                    age = rng.randint(int(interval * 2.2), 900)

                never = kind in (AccountKind.BOT, AccountKind.APPLICATION) and rng.random() < 0.09
                last_rotation = None if never else self.now - timedelta(days=age)
                automatic = rng.random() > (
                    0.22 if kind in (AccountKind.BOT, AccountKind.APPLICATION) else 0.04
                )
                has_owner = rng.random() > (
                    0.22 if kind in (AccountKind.BOT, AccountKind.APPLICATION) else 0.08
                )

                status = AccountStatus.ACTIVE
                roll = rng.random()
                if roll < 0.04:
                    status = AccountStatus.DISABLED
                elif roll < 0.06:
                    status = AccountStatus.PENDING_DELETE

                last_used = None
                if "usage_timestamps" in (system.capabilities or []):
                    last_used = self.now - timedelta(days=rng.choice([0, 1, 3, 7, 21, 60, 140, 300]))

                rows.append(
                    ManagedAccount(
                        system=system,
                        external_id=f"demo-{index}",
                        username=username,
                        container=rng.choice(safes),
                        target_address=rng.choice(HOSTS),
                        platform=f"{vendor}-standard",
                        kind=kind,
                        status=status,
                        owner_identity=rng.choice(self.owner_pool) if has_owner else "",
                        owner_team=team if rng.random() > 0.3 else "",
                        business_application=rng.choice(APPLICATIONS),
                        onboarded_at=self.now - timedelta(days=rng.randint(60, 1400)),
                        last_rotation_at=last_rotation,
                        next_rotation_due=last_rotation + timedelta(days=interval) if last_rotation else None,
                        rotation_interval_days=interval,
                        auto_rotation_enabled=automatic,
                        last_verification_at=self.now - timedelta(hours=rng.randint(1, 72)),
                        verification_ok=rng.random() > 0.05,
                        consecutive_rotation_failures=rng.choice([0] * 22 + [1, 2, 4]),
                        last_used_at=last_used,
                        exclusive_checkout=rng.random() > 0.45,
                        entitled_identity_count=rng.randint(1, 14),
                        first_seen_at=self.now - timedelta(days=rng.randint(30, 400)),
                        last_seen_at=self.now,
                    )
                )
        # A realistic number of leavers still attached to live accounts.
        for row in rng.sample([r for r in rows if r.status == AccountStatus.ACTIVE],
                              min(11, len(rows))):
            row.owner_identity = rng.choice(DEPARTED)

        ManagedAccount.objects.bulk_create(rows, batch_size=500)
        accounts = list(ManagedAccount.objects.select_related("system").all())
        self._score(accounts)
        self.stdout.write(f"Generated {len(accounts)} accounts")
        return accounts

    def _score(self, accounts) -> None:
        from collection.reconcile import compute_risk_score

        for account in accounts:
            account.risk_score = compute_risk_score(account)
        ManagedAccount.objects.bulk_update(accounts, ["risk_score"], batch_size=500)

    # ---- planted, narratable situations --------------------------------

    def _scenarios(self, systems) -> None:
        """
        Each of these is a story someone can tell, and each maps to a named rule.
        They carry recognisable usernames so the walkthrough can point at them.
        """
        corporate, payments, infrastructure = systems[0], systems[1], systems[2]
        planted: list[ManagedAccount] = []

        def plant(**fields) -> ManagedAccount:
            defaults = dict(
                system=corporate,
                platform="cyberark-standard",
                onboarded_at=self.now - timedelta(days=600),
                rotation_interval_days=90,
                verification_ok=True,
                last_verification_at=self.now - timedelta(hours=6),
                entitled_identity_count=1,
                exclusive_checkout=True,
                first_seen_at=self.now - timedelta(days=600),
                last_seen_at=self.now,
            )
            defaults.update(fields)
            account = ManagedAccount.objects.create(**defaults)
            planted.append(account)
            return account

        # BOT-001 and BOT-003: rotation switched off during an incident.
        settlement = plant(
            external_id="story-rpa-settlement",
            username="rpa_settlement_poster",
            container="RPA-BATCH",
            target_address="batch-rpa-01",
            kind=AccountKind.BOT,
            status=AccountStatus.ACTIVE,
            owner_identity="a.iyer@example.com",
            owner_team="Payments platform",
            business_application="Settlement engine",
            last_rotation_at=self.now - timedelta(days=214),
            next_rotation_due=self.now - timedelta(days=124),
            auto_rotation_enabled=False,
            last_used_at=self.now - timedelta(hours=2),
        )
        LifecycleEvent.objects.create(
            account=settlement,
            kind=LifecycleEvent.Kind.AUTO_ROTATION_DISABLED,
            occurred_at=self.now - timedelta(days=3),
            actor="j.novak@example.com",
            detail={"previous": True, "change_ticket": "CHG0044821",
                    "note": "disabled during settlement outage, restore afterwards"},
            dedupe_key="story-rpa-disabled",
        )
        self.scenarios.append((
            "BOT-001 / BOT-003",
            settlement.username,
            "Automatic rotation switched off three days ago during a settlement outage "
            "and never restored. The credential is 214 days old and in use every hour.",
        ))

        # BOT-002 and OWN-001: never rotated, no owner.
        swift = plant(
            system=payments,
            external_id="story-app-swift",
            username="app_swift_gateway",
            container="Treasury\\Interfaces",
            target_address="swift-gw-01",
            platform="delinea-standard",
            kind=AccountKind.APPLICATION,
            status=AccountStatus.ACTIVE,
            owner_identity="",
            owner_team="",
            business_application="SWIFT gateway",
            last_rotation_at=None,
            next_rotation_due=None,
            auto_rotation_enabled=False,
            onboarded_at=self.now - timedelta(days=1290),
        )
        self.scenarios.append((
            "BOT-002 / OWN-001",
            swift.username,
            "Embedded in the gateway for three and a half years, never once rotated, "
            "and no owner of record. This is the account nobody wants to touch.",
        ))

        # USE-002: break-glass pulled repeatedly with no change ticket.
        firecall = plant(
            external_id="story-firecall",
            username="firecall_domain_admin",
            container="BREAKGLASS",
            target_address="nyc-dc01.corp",
            kind=AccountKind.BREAK_GLASS,
            status=AccountStatus.ACTIVE,
            owner_identity="l.haddad@example.com",
            owner_team="Identity and access",
            business_application="Branch network",
            last_rotation_at=self.now - timedelta(days=6),
            next_rotation_due=self.now + timedelta(days=84),
            auto_rotation_enabled=True,
            last_used_at=self.now - timedelta(days=2),
        )
        for offset, actor in enumerate([
            "t.delgado@example.com", "t.delgado@example.com", "r.chen@example.com",
            "t.delgado@example.com", "b.mwangi@example.com",
        ]):
            LifecycleEvent.objects.create(
                account=firecall,
                kind=LifecycleEvent.Kind.CHECKED_OUT,
                occurred_at=self.now - timedelta(days=2 + offset * 4, hours=offset),
                actor=actor,
                source_address=ACTOR_ADDRESSES[offset % len(ACTOR_ADDRESSES)],
                ticket_reference="",
                detail={"action": "Retrieve password"},
                dedupe_key=f"story-firecall-{offset}",
            )
        self.scenarios.append((
            "USE-002",
            firecall.username,
            "Five break-glass retrievals in three weeks, none carrying a change ticket, "
            "three of them by the same person.",
        ))

        # USE-003 and SOD-001: a retrieval spike on a shared account.
        # Placed on Password Safe deliberately: it is the only platform in this
        # estate that reports how many identities are entitled to an account,
        # which is what SOD-001 needs. On the others the rule is inert, and the
        # coverage page says so rather than reporting the account as attributable.
        oracle = plant(
            system=infrastructure,
            platform="beyondtrust-standard",
            external_id="story-oracle",
            username="adm_oracle_prod",
            container="corp.example.com",
            target_address="oradb-prod-03",
            kind=AccountKind.HUMAN,
            status=AccountStatus.ACTIVE,
            owner_identity="p.tanaka@example.com",
            owner_team="Database engineering",
            business_application="Data warehouse",
            last_rotation_at=self.now - timedelta(days=12),
            next_rotation_due=self.now + timedelta(days=78),
            auto_rotation_enabled=True,
            last_used_at=self.now - timedelta(hours=1),
            exclusive_checkout=False,
            entitled_identity_count=6,
        )
        spike = []
        for day in range(2, 30):
            if self.random.random() < 0.35:
                spike.append(LifecycleEvent(
                    account=oracle,
                    kind=LifecycleEvent.Kind.CHECKED_OUT,
                    occurred_at=self.now - timedelta(days=day, hours=self.random.randint(9, 17)),
                    actor="p.tanaka@example.com",
                    source_address="10.20.30.44",
                    ticket_reference=f"INC{4000 + day}",
                    dedupe_key=f"story-oracle-base-{day}",
                ))
        for hour in range(14):
            spike.append(LifecycleEvent(
                account=oracle,
                kind=LifecycleEvent.Kind.CHECKED_OUT,
                occurred_at=self.now - timedelta(hours=hour + 1),
                actor="p.tanaka@example.com",
                source_address="172.18.4.61",
                ticket_reference="",
                dedupe_key=f"story-oracle-spike-{hour}",
            ))
        LifecycleEvent.objects.bulk_create(spike)
        self.scenarios.append((
            "USE-003 / SOD-001",
            oracle.username,
            "Fourteen retrievals in the last day against a baseline near one every three "
            "days, from an address this account has not used before. Six people are "
            "entitled to it and checkout is not exclusive, so the vault cannot say which.",
        ))

        # ROT-002 and ROT-003: rotation failing, vault out of step with the target.
        netscaler = plant(
            external_id="story-netscaler",
            username="svc_netscaler_bind",
            container="NETWORK-DEVICES",
            target_address="netscaler-02",
            kind=AccountKind.SERVICE,
            status=AccountStatus.ACTIVE,
            owner_identity="k.lindqvist@example.com",
            owner_team="Network engineering",
            business_application="Branch network",
            last_rotation_at=self.now - timedelta(days=131),
            next_rotation_due=self.now - timedelta(days=41),
            auto_rotation_enabled=True,
            verification_ok=False,
            consecutive_rotation_failures=7,
            rotation_failure_reason="Change password failed: target rejected the new value",
        )
        for attempt in range(7):
            LifecycleEvent.objects.create(
                account=netscaler,
                kind=LifecycleEvent.Kind.ROTATION_FAILED,
                occurred_at=self.now - timedelta(days=attempt * 6),
                actor="credential provider",
                outcome="failure",
                detail={"reason": netscaler.rotation_failure_reason, "consecutive": attempt + 1},
                dedupe_key=f"story-netscaler-fail-{attempt}",
            )
        self.scenarios.append((
            "ROT-002 / ROT-003",
            netscaler.username,
            "Seven consecutive rotation failures over six weeks. The vault copy no longer "
            "matches the device, so a break-glass retrieval here would fail at the moment "
            "it is needed.",
        ))

        # OWN-002: owner left, account still live and in daily use.
        treasury = plant(
            external_id="story-departed",
            username="svc_treasury_feed",
            container="UNIX-ROOT",
            target_address="pgsql-pay-01",
            kind=AccountKind.SERVICE,
            status=AccountStatus.ACTIVE,
            owner_identity=DEPARTED[0],
            owner_team="Treasury technology",
            business_application="Treasury workstation",
            last_rotation_at=self.now - timedelta(days=44),
            next_rotation_due=self.now + timedelta(days=46),
            auto_rotation_enabled=True,
            last_used_at=self.now - timedelta(days=1),
        )
        self.scenarios.append((
            "OWN-002",
            treasury.username,
            f"Owner of record {DEPARTED[0]} is no longer in the active-worker feed. The "
            "account is in daily use and would pass any recertification that only checks "
            "whether an owner field is populated.",
        ))

        # USE-001: dormant but still enabled, and rotating perfectly.
        vendor = plant(
            external_id="story-dormant-vendor",
            username="vendor_esx_support",
            container="VENDOR-ACCESS",
            target_address="esx-cluster-a",
            kind=AccountKind.VENDOR,
            status=AccountStatus.ACTIVE,
            owner_identity="e.silva@example.com",
            owner_team="Infrastructure operations",
            business_application="Collateral management",
            last_rotation_at=self.now - timedelta(days=61),
            next_rotation_due=self.now + timedelta(days=29),
            auto_rotation_enabled=True,
            last_used_at=self.now - timedelta(days=287),
        )
        self.scenarios.append((
            "USE-001",
            vendor.username,
            "A third-party support account, untouched for nine months, still enabled and "
            "still rotating on schedule. Rotation hygiene looks perfect; the account "
            "should not exist.",
        ))

        self._score(planted)

    # ---- history --------------------------------------------------------

    def _events(self, accounts) -> None:
        """Rotation and usage history, so timelines and usage baselines populate."""
        rng = self.random
        events = []
        for account in accounts:
            if account.last_rotation_at and account.rotation_interval_days:
                when = account.last_rotation_at
                for step in range(rng.randint(2, 7)):
                    events.append(LifecycleEvent(
                        account=account,
                        kind=LifecycleEvent.Kind.ROTATED,
                        occurred_at=when,
                        actor="credential provider",
                        outcome="success",
                        detail={"interval_days": account.rotation_interval_days},
                        dedupe_key=f"hist-{account.pk}-rot-{step}",
                    ))
                    when -= timedelta(days=account.rotation_interval_days + rng.randint(-3, 4))
                    if when < self.now - timedelta(days=540):
                        break

            if account.kind in (AccountKind.HUMAN, AccountKind.BREAK_GLASS) and rng.random() < 0.5:
                for pull in range(rng.randint(1, 6)):
                    events.append(LifecycleEvent(
                        account=account,
                        kind=LifecycleEvent.Kind.CHECKED_OUT,
                        occurred_at=self.now - timedelta(days=rng.randint(1, 45), hours=rng.randint(0, 20)),
                        actor=account.owner_identity or rng.choice(self.owner_pool),
                        source_address=rng.choice(ACTOR_ADDRESSES),
                        ticket_reference=f"INC{rng.randint(20000, 29999)}" if rng.random() > 0.25 else "",
                        dedupe_key=f"hist-{account.pk}-out-{pull}",
                    ))
        LifecycleEvent.objects.bulk_create(events, batch_size=1000, ignore_conflicts=True)
        self.stdout.write(f"Generated {len(events)} historical events")

    def _snapshots(self, accounts) -> None:
        """Twelve months of monthly posture for a sample, so history is not empty."""
        sample = self.random.sample(accounts, min(250, len(accounts)))
        run = CollectionRun.objects.create(
            system=sample[0].system,
            started_at=self.now - timedelta(days=365),
            finished_at=self.now - timedelta(days=365),
            outcome=CollectionRun.Outcome.SUCCESS,
        )
        rows = []
        for account in sample:
            for month in range(12):
                captured = self.now - timedelta(days=30 * month)
                age = None
                if account.last_rotation_at:
                    age = max(0, (captured - account.last_rotation_at).days)
                rows.append(AccountSnapshot(
                    account=account,
                    run=run,
                    captured_at=captured,
                    status=account.status,
                    last_rotation_at=account.last_rotation_at,
                    auto_rotation_enabled=account.auto_rotation_enabled,
                    verification_ok=account.verification_ok,
                    owner_identity=account.owner_identity,
                    credential_age_days=age,
                ))
        AccountSnapshot.objects.bulk_create(rows, batch_size=1000)

    def _runs(self, systems) -> None:
        """Recent collection history, including one platform that is failing."""
        rows = []
        for system in systems:
            seen = system.accounts.count()
            for step in range(24):
                started = self.now - timedelta(minutes=system.collection_interval_minutes * (step + 1))
                failing = system.vendor == "acme_vault_demo" and step < 6
                rows.append(CollectionRun(
                    system=system,
                    started_at=started,
                    finished_at=started + timedelta(seconds=self.random.randint(8, 190)),
                    outcome=CollectionRun.Outcome.FAILED if failing else CollectionRun.Outcome.SUCCESS,
                    accounts_seen=0 if failing else seen,
                    accounts_updated=0 if failing else seen,
                    error_message=(
                        "ConnectorError: authentication returned 401 after the collector "
                        "credential was rotated" if failing else ""
                    ),
                ))
        CollectionRun.objects.bulk_create(rows, batch_size=500)

    def _discovered(self) -> None:
        rng = self.random
        rows = []
        for index in range(34):
            rows.append(DiscoveredAccount(
                source=rng.choice(["target sweep", "Active Directory scan", "Unix inventory"]),
                username=rng.choice(["local_admin", "root_backup", "oracle", "sqlagent", "svc_legacy"]) + f"_{index}",
                target_address=rng.choice(HOSTS),
                privilege_level=rng.choice([
                    "local administrator", "root", "domain administrator", "database owner",
                ]),
                discovered_at=self.now - timedelta(days=rng.randint(9, 120)),
            ))
        DiscoveredAccount.objects.bulk_create(rows, ignore_conflicts=True)


    # ---- where credentials were used ------------------------------------

    def _usage(self, accounts) -> None:
        """
        Three tiers of usage evidence, and the residue that matters.

        Most logins are brokered by the session proxy or matched to a retrieval.
        A small number are deliberately left unexplained: a managed credential
        authenticating on a target with no checkout behind it, which is what a
        working copy living outside the vault looks like from here.
        """
        from usage.correlate import correlate, record_observations

        rng = self.random
        feeds = [
            ("Cisco Identity Services Engine", TelemetrySource.Kind.NETWORK_AAA, 30),
            ("Windows event forwarding", TelemetrySource.Kind.WINDOWS_AUTH, 60),
            ("Unix authentication collector", TelemetrySource.Kind.UNIX_AUTH, 60),
            ("Oracle unified audit", TelemetrySource.Kind.DATABASE_AUDIT, 240),
        ]
        sources = []
        for name, kind, interval in feeds:
            source, _ = TelemetrySource.objects.get_or_create(
                name=name,
                defaults={"kind": kind, "expected_interval_minutes": interval},
            )
            source.enabled = True
            source.expected_interval_minutes = interval
            # One feed is deliberately stale, so OPS-002 has something to say.
            source.last_ingest_at = (
                self.now - timedelta(days=2) if kind == TelemetrySource.Kind.DATABASE_AUDIT
                else self.now - timedelta(minutes=rng.randint(3, 40))
            )
            source.save()
            sources.append(source)

        aaa, windows, unix, database = sources
        candidates = [
            account for account in accounts
            if account.status == AccountStatus.ACTIVE
            and account.kind in (AccountKind.HUMAN, AccountKind.SERVICE, AccountKind.BREAK_GLASS)
        ]
        sampled = rng.sample(candidates, min(240, len(candidates)))

        records = []
        for account in sampled:
            asset_pool = [account.target_address] + rng.sample(HOSTS, rng.randint(0, 2))
            for _ in range(rng.randint(1, 6)):
                asset = rng.choice(asset_pool)
                feed = aaa if "rtr" in asset or "fw" in asset or "netscaler" in asset or "apic" in asset else (
                    database if "db" in asset or "sql" in asset else
                    windows if "dc" in asset or "vcenter" in asset else unix
                )
                mechanism = (
                    UsageObservation.Mechanism.NETWORK_AAA
                    if feed is aaa else UsageObservation.Mechanism.TARGET_AUTHENTICATION
                )
                occurred = self.now - timedelta(days=rng.randint(0, 28), hours=rng.randint(0, 23))

                # Most target logins get a retrieval placed just before them, so
                # the correlation pass has something honest to match against.
                explained = rng.random() > 0.06
                if explained:
                    LifecycleEvent.objects.get_or_create(
                        dedupe_key=f"usage-pair-{account.pk}-{occurred.timestamp():.0f}",
                        defaults={
                            "account": account,
                            "kind": LifecycleEvent.Kind.CHECKED_OUT,
                            "occurred_at": occurred - timedelta(minutes=rng.randint(2, 90)),
                            "actor": account.owner_identity or rng.choice(self.owner_pool),
                            "source_address": rng.choice(ACTOR_ADDRESSES),
                            "ticket_reference": f"INC{rng.randint(30000, 39999)}",
                        },
                    )

                records.append({
                    "observed_account_name": account.username,
                    "asset_identifier": asset,
                    "asset_hint": "network device" if feed is aaa else "server",
                    "occurred_at": occurred,
                    "ended_at": occurred + timedelta(minutes=rng.randint(2, 90)),
                    "mechanism": mechanism,
                    "actor": account.owner_identity,
                    "source_address": rng.choice(ACTOR_ADDRESSES),
                    "outcome": "success",
                    "command_count": rng.randint(1, 40) if feed is aaa else None,
                    "privilege_level": "15" if feed is aaa else "",
                    "dedupe_key": f"demo-usage-{account.pk}-{occurred.timestamp():.0f}-{asset}",
                    "detail": {"synthetic": True},
                    "_feed": feed,
                })

        # Brokered sessions: the tier the vault can state as fact.
        for account in rng.sample(sampled, min(90, len(sampled))):
            for _ in range(rng.randint(1, 3)):
                occurred = self.now - timedelta(days=rng.randint(0, 25), hours=rng.randint(0, 23))
                records.append({
                    "observed_account_name": account.username,
                    "asset_identifier": account.target_address,
                    "occurred_at": occurred,
                    "ended_at": occurred + timedelta(minutes=rng.randint(4, 120)),
                    "mechanism": UsageObservation.Mechanism.BROKERED_SESSION,
                    "actor": account.owner_identity or rng.choice(self.owner_pool),
                    "source_address": rng.choice(ACTOR_ADDRESSES),
                    "session_reference": f"PSM-{rng.randint(100000, 999999)}",
                    "dedupe_key": f"demo-session-{account.pk}-{occurred.timestamp():.0f}",
                    "detail": {"protocol": rng.choice(["RDP", "SSH", "SQL"])},
                    "_feed": None,
                })

        # Logins by accounts that exist in no vault at all.
        for index in range(18):
            occurred = self.now - timedelta(days=rng.randint(0, 20), hours=rng.randint(0, 23))
            records.append({
                "observed_account_name": rng.choice(["local_admin", "oracle", "root_backup", "svc_legacy_ftp"]),
                "asset_identifier": rng.choice(HOSTS),
                "occurred_at": occurred,
                "mechanism": UsageObservation.Mechanism.TARGET_AUTHENTICATION,
                "source_address": rng.choice(ACTOR_ADDRESSES),
                "dedupe_key": f"demo-unmanaged-{index}",
                "_feed": windows,
            })

        self._usage_scenarios(records)

        # Attribute each record to the feed that would really have carried it,
        # so the usage page's source column means something.
        batches: dict[int, list] = {}
        for record in records:
            feed = record.pop("_feed", None) or windows
            batches.setdefault(feed.pk, []).append(record)
        for source in sources:
            if source.pk in batches:
                record_observations(batches[source.pk], source=source)

        # Applied last: record_observations stamps a feed as current, which is
        # correct in production and would otherwise undo the deliberately stale
        # feed this demonstration needs.
        database.last_ingest_at = self.now - timedelta(days=2)
        database.save(update_fields=["last_ingest_at"])

        result = correlate()
        self.stdout.write(
            f"Recorded {len(records)} logins: {result['matched']} matched to a retrieval, "
            f"{result['unexplained']} unexplained, {result['asset_links']} credential-to-asset links"
        )

    def _usage_scenarios(self, records: list) -> None:
        """Two planted cases that only usage correlation can find."""
        rng = self.random

        # A service account whose credential is clearly embedded somewhere: it
        # authenticates on a schedule, from one host, and never via the vault.
        embedded = ManagedAccount.objects.filter(username="svc_netscaler_bind").first()
        if embedded:
            for day in range(21):
                occurred = self.now - timedelta(days=day, hours=2, minutes=rng.randint(0, 9))
                records.append({
                    "observed_account_name": embedded.username,
                    "asset_identifier": "netscaler-02",
                    "asset_hint": "network device",
                    "occurred_at": occurred,
                    "mechanism": UsageObservation.Mechanism.NETWORK_AAA,
                    "source_address": "10.44.2.17",
                    "privilege_level": "15",
                    "command_count": 3,
                    "dedupe_key": f"story-embedded-{day}",
                    "detail": {"note": "same host, same minute each night"},
                    "_feed": None,
                })
            self.scenarios.append((
                "USE-004",
                embedded.username,
                "Authenticates on the device at 02:00 every night from the same host, and "
                "the vault has no record of handing the credential out on any of those "
                "occasions. It is embedded in a script somewhere.",
            ))

        # A domain administrator account whose reach is far wider than its mapping.
        wide = ManagedAccount.objects.filter(username="adm_oracle_prod").first()
        if wide:
            for asset in HOSTS[:14]:
                for _ in range(rng.randint(1, 3)):
                    occurred = self.now - timedelta(days=rng.randint(0, 26), hours=rng.randint(8, 20))
                    records.append({
                        "observed_account_name": wide.username,
                        "asset_identifier": asset,
                        "occurred_at": occurred,
                        "mechanism": UsageObservation.Mechanism.TARGET_AUTHENTICATION,
                        "actor": wide.owner_identity,
                        "source_address": rng.choice(ACTOR_ADDRESSES),
                        "dedupe_key": f"story-wide-{asset}-{occurred.timestamp():.0f}",
                        "_feed": None,
                    })
            self.scenarios.append((
                "USE-005 / USE-007",
                wide.username,
                "Mapped in the vault to one database host, observed logging in to fourteen "
                "systems across three asset types. That is the blast radius of one leak, and "
                "the reason nobody wants to rotate it.",
            ))


    # ---- developer and bot access ---------------------------------------

    def _access(self, accounts) -> None:
        """
        Repositories, the people and bots with access to them, and the two
        residues that only reconciliation finds: access nobody approved, and
        expiries that never took effect.
        """
        from access.models import (
            AccessGrant, AccessLevel, AccessRequest, ApprovalPolicy, ApprovalStep,
            Approver, Criticality, Principal, PrincipalType, Resource, ResourcePlatform,
        )
        from access.reconcile import reconcile_access
        from access.workflow import decide, hand_off, submit
        from resources.base import NormalizedAccess

        rng = self.random

        repositories = [
            ("acme-bank/payments-core", True, Criticality.CRITICAL, "Payments platform"),
            ("acme-bank/settlement-engine", True, Criticality.CRITICAL, "Payments platform"),
            ("acme-bank/swift-gateway", True, Criticality.CRITICAL, "Treasury technology"),
            ("acme-bank/network-automation", True, Criticality.HIGH, "Network engineering"),
            ("acme-bank/branch-portal", True, Criticality.HIGH, "Branch technology"),
            ("acme-bank/reporting-pipeline", False, Criticality.MODERATE, "Data engineering"),
            ("acme-bank/infra-terraform", True, Criticality.CRITICAL, "Infrastructure operations"),
            ("acme-bank/sandbox", False, Criticality.LOW, "Platform engineering"),
            ("platform/ci-templates", False, Criticality.MODERATE, "Platform engineering"),
            ("platform/device-configs", True, Criticality.HIGH, "Network engineering"),
        ]
        resources = []
        for identifier, production, criticality, team in repositories:
            platform = ResourcePlatform.GITLAB if identifier.startswith("platform/") else ResourcePlatform.GITHUB
            resource, _ = Resource.objects.get_or_create(
                platform=platform,
                identifier=identifier,
                defaults={
                    "display_name": identifier.split("/")[-1],
                    "production": production,
                    "criticality": criticality,
                    "owner_team": team,
                    "owner_identity": rng.choice(self.owner_pool),
                    "business_application": rng.choice(APPLICATIONS),
                },
            )
            resources.append(resource)

        ApprovalPolicy.objects.get_or_create(
            name="Production repositories",
            defaults={
                "applies_to_production_only": True,
                "access_levels": [AccessLevel.WRITE, AccessLevel.MAINTAIN, AccessLevel.ADMIN, AccessLevel.DEPLOY],
                "approvals_required": 2,
                "approver_groups": ["repo-owners", "security"],
                "maximum_duration_days": 14,
                "require_owner_for_bots": True,
                "notes": "Two approvals, one of them independent. Fourteen day ceiling.",
            },
        )
        ApprovalPolicy.objects.get_or_create(
            name="Everything else",
            defaults={"approvals_required": 1, "maximum_duration_days": 30,
                      "require_ticket_reference": False, "require_justification": False},
        )
        for identifier, groups, team, independent in [
            ("owner.payments@example.com", ["repo-owners"], "Payments platform", False),
            ("owner.network@example.com", ["repo-owners"], "Network engineering", False),
            ("sec.review@example.com", ["security"], "Security", True),
            ("sec.duty@example.com", ["security"], "Security", True),
        ]:
            Approver.objects.get_or_create(
                identifier=identifier,
                defaults={"groups": groups, "team": team, "independent": independent},
            )

        developers = []
        for index, surname in enumerate(SURNAMES[:12]):
            developer, _ = Principal.objects.get_or_create(
                identifier=f"{surname[0]}.{surname}",
                defaults={
                    "display_name": surname.title(),
                    "email": f"{surname[0]}.{surname}@example.com",
                    "principal_type": PrincipalType.DEVELOPER,
                    "team": rng.choice(TEAMS),
                },
            )
            developers.append(developer)

        # Bots, including one linked to a vaulted credential that is not rotating.
        stale_credential = ManagedAccount.objects.filter(username="rpa_settlement_poster").first()
        bots = []
        for name, owner, account in [
            ("rpa-settlement[bot]", "a.iyer@example.com", stale_credential),
            ("ci-deploy[bot]", "j.novak@example.com", None),
            ("dependency-updater[bot]", "", None),
            ("deploy-key:acme-bank/swift-gateway:41", "", None),
            ("terraform-runner[bot]", "e.silva@example.com", None),
        ]:
            bot, _ = Principal.objects.get_or_create(
                identifier=name,
                defaults={
                    "principal_type": PrincipalType.BOT,
                    "responsible_owner": owner,
                    "managed_account": account,
                },
            )
            bots.append(bot)

        # A governed request that went all the way through.
        governed = None
        try:
            governed = submit(
                principal=developers[0],
                resource=resources[0],
                access_level=AccessLevel.WRITE,
                requested_by="lead.payments@example.com",
                justification="Settlement retry work for CHG0044821, two week window",
                ticket_reference="CHG0044821",
                requested_days=14,
            )
            decide(governed, approver_identity="owner.payments@example.com",
                   decision=ApprovalStep.Decision.APPROVED, comment="Scope agreed")
            decide(governed, approver_identity="sec.review@example.com",
                   decision=ApprovalStep.Decision.APPROVED, comment="Time-bounded, no objection")
            governed.refresh_from_db()
            hand_off(governed, system="ServiceNow", reference="RITM0099887")
            governed.refresh_from_db()
        except Exception as exc:
            self.stdout.write(self.style.WARNING(f"  governed request skipped: {exc}"))

        # Requests waiting on a decision.
        for developer, resource in zip(developers[1:5], resources[1:5]):
            try:
                pending = submit(
                    principal=developer, resource=resource,
                    access_level=rng.choice([AccessLevel.WRITE, AccessLevel.MAINTAIN]),
                    requested_by=f"lead.{developer.team.split()[0].lower()}@example.com",
                    justification="Delivery work on the current sprint",
                    ticket_reference=f"CHG00{rng.randint(40000, 49999)}",
                    requested_days=rng.choice([7, 14]),
                )
                pending.created_at = self.now - timedelta(days=rng.randint(1, 9))
                pending.save(update_fields=["created_at"])
                if rng.random() > 0.5:
                    decide(pending, approver_identity="owner.payments@example.com",
                           decision=ApprovalStep.Decision.APPROVED)
            except Exception:
                continue

        # What the platforms actually report. Most of it has no request behind
        # it, which is the ordinary state of a real estate.
        for resource in resources:
            records = []
            if governed and resource == resources[0]:
                records.append(NormalizedAccess(
                    resource_identifier=resource.identifier,
                    principal_identifier=developers[0].identifier,
                    access_level=AccessLevel.WRITE,
                ))
            for developer in rng.sample(developers, rng.randint(3, 8)):
                records.append(NormalizedAccess(
                    resource_identifier=resource.identifier,
                    principal_identifier=developer.identifier,
                    email=developer.email,
                    access_level=rng.choice([
                        AccessLevel.READ, AccessLevel.READ, AccessLevel.WRITE,
                        AccessLevel.WRITE, AccessLevel.MAINTAIN,
                    ]),
                    last_used_at=self.now - timedelta(days=rng.choice([0, 2, 9, 40, 130, 260])),
                ))
            for bot in rng.sample(bots, rng.randint(1, 3)):
                records.append(NormalizedAccess(
                    resource_identifier=resource.identifier,
                    principal_identifier=bot.identifier,
                    access_level=rng.choice([AccessLevel.WRITE, AccessLevel.WRITE, AccessLevel.ADMIN]),
                    machine_identity=True,
                    last_used_at=self.now - timedelta(days=rng.choice([0, 1, 5, 200])),
                ))
            reconcile_access(resource, records)

        # Backdate so the age thresholds mean something.
        for grant in AccessGrant.objects.all():
            grant.granted_at = self.now - timedelta(days=rng.randint(10, 500))
            grant.save(update_fields=["granted_at"])

        # An expiry that never took effect: the register says gone, the platform
        # says otherwise.
        expired = AccessGrant.objects.filter(
            resource__production=True, access_level=AccessLevel.WRITE
        ).order_by("?")[:4]
        for grant in expired:
            grant.expires_at = self.now - timedelta(days=rng.randint(6, 70))
            grant.save(update_fields=["expires_at"])

        self._access_scenarios(resources, bots, stale_credential)

        self.stdout.write(
            f"Access: {Resource.objects.count()} resources, {Principal.objects.count()} principals, "
            f"{AccessGrant.objects.count()} grants "
            f"({AccessGrant.objects.filter(origin=AccessGrant.Origin.DISCOVERED).count()} unapproved), "
            f"{AccessRequest.objects.count()} requests"
        )

    def _access_scenarios(self, resources, bots, stale_credential) -> None:
        from access.models import AccessGrant, AccessLevel, Principal, PrincipalType, Resource
        from access.reconcile import reconcile_access
        from resources.base import NormalizedAccess

        swift = next((r for r in resources if "swift" in r.identifier), None)
        settlement = next((r for r in resources if "settlement" in r.identifier), None)

        # A bot with production write access whose vaulted credential has not
        # rotated in seven months. Each half is unremarkable in its own register.
        if settlement and stale_credential:
            bot = Principal.objects.get(identifier="rpa-settlement[bot]")
            reconcile_access(settlement, [NormalizedAccess(
                resource_identifier=settlement.identifier,
                principal_identifier=bot.identifier,
                access_level=AccessLevel.WRITE,
                machine_identity=True,
                last_used_at=self.now - timedelta(hours=3),
            )])
            AccessGrant.objects.filter(principal=bot, resource=settlement).update(
                granted_at=self.now - timedelta(days=420), expires_at=None
            )
            self.scenarios.append((
                "ACC-006",
                "rpa-settlement[bot]",
                "Writes to the settlement repository and authenticates with a credential that "
                "has not rotated in 214 days. Neither half looks urgent on its own; the access "
                "register and the vault register are owned by different teams.",
            ))

        # A deploy key: repository write access with no person attached and no
        # approval behind it.
        if swift:
            key = Principal.objects.get(identifier="deploy-key:acme-bank/swift-gateway:41")
            reconcile_access(swift, [NormalizedAccess(
                resource_identifier=swift.identifier,
                principal_identifier=key.identifier,
                access_level=AccessLevel.WRITE,
                machine_identity=True,
            )])
            AccessGrant.objects.filter(principal=key).update(
                granted_at=self.now - timedelta(days=760), expires_at=None
            )
            self.scenarios.append((
                "ACC-001 / ACC-003 / ACC-005",
                "deploy-key:acme-bank/swift-gateway:41",
                "A deploy key with write access to the payment gateway repository, created two "
                "years ago, no expiry, no approval behind it, and no human named against it. "
                "A recertification campaign aimed at people never sees it.",
            ))

    # ---- make the queue look worked, not freshly dumped -----------------

    def _triage(self) -> None:
        rng = self.random

        # Spread the open dates so the age column means something. Rules that
        # describe a long-standing condition get older findings than the ones
        # describing something that just happened.
        recent = {"BOT-003", "USE-002", "USE-003", "OPS-001"}
        aged = []
        for finding in Finding.objects.all():
            span = 6 if finding.rule_id in recent else rng.choice([3, 14, 45, 120, 260])
            finding.opened_at = self.now - timedelta(days=rng.randint(0, span),
                                                     hours=rng.randint(0, 23))
            aged.append(finding)
        Finding.objects.bulk_update(aged, ["opened_at"], batch_size=500)

        findings = list(Finding.objects.filter(state=Finding.State.OPEN).order_by("?")[:140])
        acknowledged, suppressed = findings[:55], findings[55:80]
        for finding in acknowledged:
            finding.state = Finding.State.ACKNOWLEDGED
            finding.assigned_to = rng.choice(self.owner_pool)
            finding.ticket_reference = f"RITM{rng.randint(100000, 199999)}"
        for finding in suppressed:
            finding.state = Finding.State.SUPPRESSED
            finding.assigned_to = rng.choice(self.owner_pool)
            finding.suppressed_until = self.now + timedelta(days=rng.choice([14, 30, 60, 90]))
            finding.suppression_reason = rng.choice([
                "Application owner holds an approved exception until the platform upgrade lands",
                "Vendor confirmed the target cannot accept programmatic rotation; compensating monitoring in place",
                "Decommission scheduled; the account is removed at cutover",
            ])
        Finding.objects.bulk_update(
            acknowledged + suppressed,
            ["state", "assigned_to", "ticket_reference", "suppressed_until", "suppression_reason"],
            batch_size=200,
        )

        # A tuned rule, so the configuration story is visible too.
        RuleConfiguration.objects.update_or_create(
            rule_id="USE-001",
            defaults={
                "enabled": True,
                "parameters": {"dormant_days": 120},
                "exempt_containers": ["BREAKGLASS"],
                "updated_by": "identity.governance@example.com",
            },
        )

    # ---- what to show ---------------------------------------------------

    def _walkthrough(self) -> None:
        self.stdout.write(self.style.MIGRATE_HEADING("\nPlanted situations worth walking through"))
        for rule_ids, username, story in self.scenarios:
            self.stdout.write(f"\n  {self.style.WARNING(rule_ids)}  {username}")
            for line in textwrap.wrap(story, 84):
                self.stdout.write(f"      {line}")

        self.stdout.write(self.style.MIGRATE_HEADING("\n\nSuggested order"))
        steps = [
            "Posture: the estate in four numbers, then the credential age histogram.",
            "Coverage: five platforms with different feeds. Hatched cells are detections that "
            "cannot run there. Acme Vault is stale and failing authentication, so its column is "
            "blind rather than clean.",
            "Findings filtered to critical: work the queue, and note the acknowledged and "
            "suppressed rows carrying tickets and expiry dates.",
            "Account detail for rpa_settlement_poster: the timeline shows rotation switched off "
            "three days ago, by whom, with the change ticket.",
            "Configuration, then 'manage.py validate_connector', to show a platform being "
            "onboarded without writing anything.",
        ]
        for step in steps:
            for number, line in enumerate(textwrap.wrap(step, 84)):
                self.stdout.write(f"  {'-' if number == 0 else ' '} {line}")
        self.stdout.write(
            "\n  Verify with: python manage.py doctor   (run it in the shell that starts the server)\n"
        )
