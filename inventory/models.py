"""
The normalized warehouse.

Vendor-specific vocabulary stops at the connector boundary. Everything below
this line -- rules, dashboard, export -- reads only these tables, which is what
makes it possible to add a fifth Privileged Access Management platform without
touching a detection.
"""

from __future__ import annotations

from datetime import timedelta

from django.db import models
from django.db.models import Q
from django.utils import timezone


class AccountKind(models.TextChoices):
    HUMAN = "human", "Human administrator"
    SERVICE = "service", "Service account"
    BOT = "bot", "Robotic process account"
    APPLICATION = "application", "Application identity"
    BREAK_GLASS = "break_glass", "Break glass"
    VENDOR = "vendor", "Third party"
    UNKNOWN = "unknown", "Unclassified"


NON_HUMAN_KINDS = [AccountKind.SERVICE, AccountKind.BOT, AccountKind.APPLICATION]


class AccountStatus(models.TextChoices):
    ACTIVE = "active", "Active"
    DISABLED = "disabled", "Disabled"
    PENDING_DELETE = "pending_delete", "Pending deletion"
    DELETED = "deleted", "Deleted"
    UNKNOWN = "unknown", "Unknown"


class Severity(models.TextChoices):
    CRITICAL = "critical", "Critical"
    HIGH = "high", "High"
    MEDIUM = "medium", "Medium"
    LOW = "low", "Low"
    INFO = "info", "Informational"


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class PamSystem(models.Model):
    """One Privileged Access Management deployment being collected from."""

    name = models.CharField(max_length=120, unique=True)
    vendor = models.CharField(max_length=40)
    base_url = models.URLField()
    environment = models.CharField(max_length=40, default="production")
    # Never stores a credential. Holds a pointer such as env:PAM_CYBERARK_PROD.
    credential_reference = models.CharField(max_length=200)
    options = models.JSONField(default=dict, blank=True)
    #: Refreshed from the connector on every successful collection, so the rule
    #: engine and the coverage view can reason about what this platform can
    #: supply without holding credentials or opening a connection.
    capabilities = models.JSONField(default=list, blank=True)
    enabled = models.BooleanField(default=True)
    collection_interval_minutes = models.PositiveIntegerField(default=60)
    last_successful_collection = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return f"{self.name} ({self.vendor})"

    def supports(self, capability: str) -> bool:
        return capability in (self.capabilities or [])

    @property
    def collection_overdue(self) -> bool:
        if not self.last_successful_collection:
            return True
        deadline = self.last_successful_collection + timedelta(
            minutes=self.collection_interval_minutes * 2
        )
        return timezone.now() > deadline


class CollectionRun(models.Model):
    class Outcome(models.TextChoices):
        RUNNING = "running", "Running"
        SUCCESS = "success", "Success"
        PARTIAL = "partial", "Partial"
        FAILED = "failed", "Failed"

    system = models.ForeignKey(PamSystem, on_delete=models.CASCADE, related_name="runs")
    started_at = models.DateTimeField(default=timezone.now)
    finished_at = models.DateTimeField(null=True, blank=True)
    outcome = models.CharField(max_length=16, choices=Outcome.choices, default=Outcome.RUNNING)
    accounts_seen = models.PositiveIntegerField(default=0)
    accounts_created = models.PositiveIntegerField(default=0)
    accounts_updated = models.PositiveIntegerField(default=0)
    accounts_retired = models.PositiveIntegerField(default=0)
    activities_ingested = models.PositiveIntegerField(default=0)
    error_message = models.TextField(blank=True)

    class Meta:
        ordering = ["-started_at"]
        indexes = [models.Index(fields=["system", "-started_at"])]

    @property
    def duration_seconds(self) -> float | None:
        if not self.finished_at:
            return None
        return (self.finished_at - self.started_at).total_seconds()


class ManagedAccountQuerySet(models.QuerySet):
    def live(self):
        return self.exclude(status=AccountStatus.DELETED)

    def non_human(self):
        return self.filter(kind__in=NON_HUMAN_KINDS)

    def rotation_overdue(self, grace_days: int = 0):
        now = timezone.now()
        return self.live().filter(
            Q(next_rotation_due__lt=now - timedelta(days=grace_days))
            | Q(next_rotation_due__isnull=True, last_rotation_at__lt=now - timedelta(days=90))
        )


class ManagedAccount(models.Model):
    """
    Current known state of one privileged credential.

    Deliberately absent: any field that could hold or hint at the credential
    value. The `raw` column is scrubbed by connectors.base.scrub before it
    reaches here.
    """

    system = models.ForeignKey(PamSystem, on_delete=models.CASCADE, related_name="accounts")
    external_id = models.CharField(max_length=200)

    username = models.CharField(max_length=256)
    container = models.CharField(max_length=256, blank=True)
    target_address = models.CharField(max_length=256, blank=True)
    platform = models.CharField(max_length=128, blank=True)

    kind = models.CharField(max_length=20, choices=AccountKind.choices, default=AccountKind.UNKNOWN)
    status = models.CharField(max_length=20, choices=AccountStatus.choices, default=AccountStatus.UNKNOWN)

    owner_identity = models.CharField(max_length=200, blank=True)
    owner_team = models.CharField(max_length=200, blank=True)
    business_application = models.CharField(max_length=200, blank=True)

    onboarded_at = models.DateTimeField(null=True, blank=True)
    last_rotation_at = models.DateTimeField(null=True, blank=True)
    next_rotation_due = models.DateTimeField(null=True, blank=True)
    rotation_interval_days = models.PositiveIntegerField(null=True, blank=True)
    auto_rotation_enabled = models.BooleanField(null=True, blank=True)

    last_verification_at = models.DateTimeField(null=True, blank=True)
    verification_ok = models.BooleanField(null=True, blank=True)
    last_rotation_failed = models.BooleanField(default=False)
    rotation_failure_reason = models.CharField(max_length=400, blank=True)
    consecutive_rotation_failures = models.PositiveIntegerField(default=0)

    last_used_at = models.DateTimeField(null=True, blank=True)
    exclusive_checkout = models.BooleanField(null=True, blank=True)
    entitled_identity_count = models.PositiveIntegerField(null=True, blank=True)

    first_seen_at = models.DateTimeField(default=timezone.now)
    last_seen_at = models.DateTimeField(default=timezone.now)
    retired_at = models.DateTimeField(null=True, blank=True)

    risk_score = models.PositiveSmallIntegerField(default=0)
    raw = models.JSONField(default=dict, blank=True)

    objects = ManagedAccountQuerySet.as_manager()

    class Meta:
        unique_together = [("system", "external_id")]
        ordering = ["system", "container", "username"]
        indexes = [
            models.Index(fields=["kind", "status"]),
            models.Index(fields=["next_rotation_due"]),
            models.Index(fields=["last_rotation_at"]),
            models.Index(fields=["owner_identity"]),
        ]

    def __str__(self) -> str:
        return f"{self.username}@{self.target_address or self.container}"

    # -- derived lifecycle properties -----------------------------------

    @property
    def credential_age_days(self) -> int | None:
        if not self.last_rotation_at:
            return None
        return (timezone.now() - self.last_rotation_at).days

    @property
    def days_overdue(self) -> int | None:
        if not self.next_rotation_due:
            return None
        delta = (timezone.now() - self.next_rotation_due).days
        return delta if delta > 0 else 0

    @property
    def rotation_pressure(self) -> float:
        """
        Age as a fraction of the policy interval. 1.0 means due now, above 1.0
        means overdue. This is the number the dashboard meters render.
        """
        age = self.credential_age_days
        if age is None:
            return 1.5 if self.status == AccountStatus.ACTIVE else 0.0
        interval = self.rotation_interval_days or 90
        return round(age / max(interval, 1), 3)

    @property
    def dormant_days(self) -> int | None:
        if not self.last_used_at:
            return None
        return (timezone.now() - self.last_used_at).days

    @property
    def is_non_human(self) -> bool:
        return self.kind in {k.value for k in NON_HUMAN_KINDS}


class AccountSnapshot(models.Model):
    """Point-in-time lifecycle state, written once per collection run per account."""

    account = models.ForeignKey(ManagedAccount, on_delete=models.CASCADE, related_name="snapshots")
    run = models.ForeignKey(CollectionRun, on_delete=models.CASCADE, related_name="snapshots")
    captured_at = models.DateTimeField(default=timezone.now)
    status = models.CharField(max_length=20)
    last_rotation_at = models.DateTimeField(null=True, blank=True)
    auto_rotation_enabled = models.BooleanField(null=True, blank=True)
    verification_ok = models.BooleanField(null=True, blank=True)
    owner_identity = models.CharField(max_length=200, blank=True)
    credential_age_days = models.IntegerField(null=True, blank=True)

    class Meta:
        ordering = ["-captured_at"]
        indexes = [models.Index(fields=["account", "-captured_at"])]


class LifecycleEvent(models.Model):
    """
    Derived transitions plus ingested vendor audit events. This is the table
    that gets forwarded downstream; it is the event stream, not the inventory.
    """

    class Kind(models.TextChoices):
        ONBOARDED = "onboarded", "Onboarded"
        ROTATED = "rotated", "Rotated"
        ROTATION_FAILED = "rotation_failed", "Rotation failed"
        VERIFICATION_FAILED = "verification_failed", "Verification failed"
        OWNERSHIP_CHANGED = "ownership_changed", "Ownership changed"
        AUTO_ROTATION_DISABLED = "auto_rotation_disabled", "Automatic rotation disabled"
        AUTO_ROTATION_ENABLED = "auto_rotation_enabled", "Automatic rotation enabled"
        STATUS_CHANGED = "status_changed", "Status changed"
        RETIRED = "retired", "Removed from vault"
        CHECKED_OUT = "checked_out", "Checked out"
        CHECKED_IN = "checked_in", "Checked in"
        VENDOR_AUDIT = "vendor_audit", "Vendor audit event"

    account = models.ForeignKey(ManagedAccount, on_delete=models.CASCADE, related_name="events")
    kind = models.CharField(max_length=32, choices=Kind.choices)
    occurred_at = models.DateTimeField()
    recorded_at = models.DateTimeField(default=timezone.now)
    actor = models.CharField(max_length=200, blank=True)
    source_address = models.CharField(max_length=64, blank=True)
    outcome = models.CharField(max_length=20, blank=True)
    ticket_reference = models.CharField(max_length=80, blank=True)
    detail = models.JSONField(default=dict, blank=True)
    dedupe_key = models.CharField(max_length=300, unique=True)
    exported_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-occurred_at"]
        indexes = [
            models.Index(fields=["-occurred_at"]),
            models.Index(fields=["kind", "-occurred_at"]),
            models.Index(fields=["exported_at"]),
        ]


class Finding(models.Model):
    """
    An open policy violation. Findings are stateful: the rule engine opens one
    when a condition first holds and closes it when the condition clears, so
    the dashboard shows a work queue rather than a re-alerting firehose.
    """

    class State(models.TextChoices):
        OPEN = "open", "Open"
        ACKNOWLEDGED = "acknowledged", "Acknowledged"
        SUPPRESSED = "suppressed", "Suppressed"
        RESOLVED = "resolved", "Resolved"

    rule_id = models.CharField(max_length=32)
    #: What the finding is about, when that is not the managed account itself:
    #: a principal, a telemetry feed, an unvaulted account name. Without it,
    #: every finding a rule raises against the same anchor account collapses
    #: into one row and the queue silently under-reports.
    subject_key = models.CharField(max_length=200, blank=True)
    title = models.CharField(max_length=200)
    category = models.CharField(max_length=40)
    severity = models.CharField(max_length=12, choices=Severity.choices)
    account = models.ForeignKey(
        ManagedAccount, on_delete=models.CASCADE, related_name="findings", null=True, blank=True
    )
    system = models.ForeignKey(PamSystem, on_delete=models.CASCADE, related_name="findings")

    state = models.CharField(max_length=16, choices=State.choices, default=State.OPEN)
    opened_at = models.DateTimeField(default=timezone.now)
    last_seen_at = models.DateTimeField(default=timezone.now)
    resolved_at = models.DateTimeField(null=True, blank=True)
    suppressed_until = models.DateTimeField(null=True, blank=True)
    suppression_reason = models.TextField(blank=True)
    assigned_to = models.CharField(max_length=200, blank=True)
    ticket_reference = models.CharField(max_length=80, blank=True)
    evidence = models.JSONField(default=dict, blank=True)
    exported_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = [("rule_id", "account", "subject_key", "opened_at")]
        ordering = ["severity", "-opened_at"]
        indexes = [
            models.Index(fields=["state", "severity"]),
            models.Index(fields=["rule_id", "state"]),
            models.Index(fields=["rule_id", "subject_key"]),
            models.Index(fields=["exported_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.rule_id} {self.account or self.system}"

    @property
    def age_days(self) -> int:
        return (timezone.now() - self.opened_at).days

    @property
    def is_active(self) -> bool:
        if self.state in (self.State.RESOLVED,):
            return False
        if self.state == self.State.SUPPRESSED and self.suppressed_until:
            return timezone.now() > self.suppressed_until
        return self.state != self.State.SUPPRESSED


class RuleConfiguration(models.Model):
    """Per-deployment tuning without a code change."""

    rule_id = models.CharField(max_length=32, unique=True)
    enabled = models.BooleanField(default=True)
    severity_override = models.CharField(max_length=12, choices=Severity.choices, blank=True)
    parameters = models.JSONField(default=dict, blank=True)
    exempt_containers = models.JSONField(default=list, blank=True)
    exempt_account_ids = models.JSONField(default=list, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=200, blank=True)

    class Meta:
        ordering = ["rule_id"]

    def __str__(self) -> str:
        return self.rule_id


class DiscoveredAccount(models.Model):
    """
    Privileged accounts found on target systems by a discovery scan but not
    present in any vault. The gap between this table and ManagedAccount is the
    single most useful number the dashboard produces.
    """

    source = models.CharField(max_length=80)
    username = models.CharField(max_length=256)
    target_address = models.CharField(max_length=256)
    privilege_level = models.CharField(max_length=80, blank=True)
    discovered_at = models.DateTimeField(default=timezone.now)
    last_seen_at = models.DateTimeField(default=timezone.now)
    onboarded = models.BooleanField(default=False)
    matched_account = models.ForeignKey(
        ManagedAccount, on_delete=models.SET_NULL, null=True, blank=True, related_name="discoveries"
    )
    detail = models.JSONField(default=dict, blank=True)

    class Meta:
        unique_together = [("source", "username", "target_address")]
        ordering = ["target_address", "username"]


# ==========================================================================
# Where credentials actually get used
#
# A vault records retrieval. It does not record use. Once a credential leaves
# the vault, the vault is blind -- which means "who checked it out" and "what it
# was used on" are different questions, and only the first has an easy answer.
#
# Three tiers of fidelity, in descending order of certainty:
#
#   1. Brokered sessions. The vault proxied the connection, so it knows the
#      exact target, the duration, and often the commands. Certain.
#   2. Application fetches. The credential provider records an application
#      identity and the requesting host. Certain as to which application, and
#      as to where it ran.
#   3. Target-side authentication telemetry, correlated back. Network device
#      accounting, Windows security events, Unix authentication logs, database
#      audit. Joined to a retrieval on account, target, and time window.
#      Inferred, not certain -- but it is the only tier that sees a direct
#      connection made outside the vault's session proxy.
#
# Tier three is where the value is, and not because it completes the picture.
# It is because an authentication with no matching retrieval means a working
# copy of that credential exists somewhere outside the vault.
# ==========================================================================


class AssetType(models.TextChoices):
    NETWORK_DEVICE = "network_device", "Network device"
    SERVER = "server", "Server"
    DATABASE = "database", "Database"
    APPLICATION = "application", "Application"
    HYPERVISOR = "hypervisor", "Hypervisor"
    CLOUD_ACCOUNT = "cloud_account", "Cloud account"
    DIRECTORY = "directory", "Directory"
    UNKNOWN = "unknown", "Unclassified"


class TargetAsset(models.Model):
    """A device, application, or system a privileged credential can log in to."""

    identifier = models.CharField(max_length=256, unique=True)
    display_name = models.CharField(max_length=256, blank=True)
    asset_type = models.CharField(max_length=20, choices=AssetType.choices, default=AssetType.UNKNOWN)
    environment = models.CharField(max_length=40, blank=True)
    criticality = models.CharField(max_length=20, blank=True)
    owner_team = models.CharField(max_length=120, blank=True)
    address = models.CharField(max_length=120, blank=True)
    first_seen_at = models.DateTimeField(default=timezone.now)
    last_seen_at = models.DateTimeField(default=timezone.now)
    detail = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["identifier"]
        indexes = [models.Index(fields=["asset_type"]), models.Index(fields=["environment"])]

    def __str__(self) -> str:
        return self.display_name or self.identifier


class TelemetrySource(models.Model):
    """
    A feed of target-side authentication records. These do not come from the
    vault -- they come from the systems being logged in to, which is precisely
    why they can see logins the vault never brokered.
    """

    class Kind(models.TextChoices):
        NETWORK_AAA = "network_aaa", "Network device accounting (TACACS+ or RADIUS)"
        WINDOWS_AUTH = "windows_auth", "Windows security events"
        UNIX_AUTH = "unix_auth", "Unix authentication and privilege escalation"
        DATABASE_AUDIT = "database_audit", "Database audit"
        CLOUD_TRAIL = "cloud_trail", "Cloud provider audit trail"
        SESSION_PROXY = "session_proxy", "Privileged session proxy"

    name = models.CharField(max_length=120, unique=True)
    kind = models.CharField(max_length=20, choices=Kind.choices)
    enabled = models.BooleanField(default=True)
    #: Where records arrive from: a directory the enterprise event platform
    #: drops exports into, or an endpoint. Never holds a credential.
    ingest_reference = models.CharField(max_length=300, blank=True)
    #: Registered collector key for a feed this system pulls itself. Blank means
    #: the feed is delivered as files and parsed from ingest_reference.
    collector = models.CharField(max_length=40, blank=True)
    #: Collector configuration: host, view names, glob patterns. No credentials.
    settings = models.JSONField(default=dict, blank=True)
    #: Pointer such as env:ISE_DATA_CONNECT. Resolved at runtime, never stored.
    credential_reference = models.CharField(max_length=200, blank=True)
    #: Where the last pull stopped: a timestamp, or a file and byte offset.
    cursor = models.JSONField(default=dict, blank=True)
    expected_interval_minutes = models.PositiveIntegerField(default=60)
    last_ingest_at = models.DateTimeField(null=True, blank=True)
    records_ingested = models.PositiveIntegerField(default=0)
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name

    @property
    def stale(self) -> bool:
        if not self.enabled:
            return False
        if not self.last_ingest_at:
            return True
        return timezone.now() > self.last_ingest_at + timedelta(
            minutes=self.expected_interval_minutes * 2
        )


class UsageObservation(models.Model):
    """One observed login by a privileged credential onto a target asset."""

    class Mechanism(models.TextChoices):
        BROKERED_SESSION = "brokered_session", "Session brokered by the vault"
        APPLICATION_FETCH = "application_fetch", "Credential provider fetch by an application"
        TARGET_AUTHENTICATION = "target_authentication", "Authentication seen on the target"
        NETWORK_AAA = "network_aaa", "Network device accounting record"

    class Correlation(models.TextChoices):
        BROKERED = "brokered", "Brokered by the vault, no correlation needed"
        MATCHED = "matched", "Matched to a vault retrieval"
        UNEXPLAINED = "unexplained", "No vault retrieval accounts for this login"
        UNMATCHED_ACCOUNT = "unmatched_account", "Account is not managed in any vault"
        PENDING = "pending", "Not yet correlated"

    account = models.ForeignKey(
        ManagedAccount, on_delete=models.CASCADE, related_name="usage", null=True, blank=True
    )
    #: The account name exactly as the target reported it, before matching.
    observed_account_name = models.CharField(max_length=256)
    asset = models.ForeignKey(TargetAsset, on_delete=models.CASCADE, related_name="usage")
    source = models.ForeignKey(
        TelemetrySource, on_delete=models.SET_NULL, null=True, blank=True, related_name="observations"
    )

    occurred_at = models.DateTimeField()
    ended_at = models.DateTimeField(null=True, blank=True)
    mechanism = models.CharField(max_length=24, choices=Mechanism.choices)
    correlation = models.CharField(max_length=20, choices=Correlation.choices, default=Correlation.PENDING)
    correlated_event = models.ForeignKey(
        LifecycleEvent, on_delete=models.SET_NULL, null=True, blank=True, related_name="usage"
    )
    correlation_lag_seconds = models.IntegerField(null=True, blank=True)

    actor = models.CharField(max_length=200, blank=True)
    source_address = models.CharField(max_length=64, blank=True)
    outcome = models.CharField(max_length=20, default="success")
    session_reference = models.CharField(max_length=120, blank=True)
    command_count = models.PositiveIntegerField(null=True, blank=True)
    privilege_level = models.CharField(max_length=40, blank=True)
    detail = models.JSONField(default=dict, blank=True)
    dedupe_key = models.CharField(max_length=300, unique=True)
    exported_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-occurred_at"]
        indexes = [
            models.Index(fields=["-occurred_at"]),
            models.Index(fields=["correlation", "-occurred_at"]),
            models.Index(fields=["account", "asset"]),
            models.Index(fields=["mechanism"]),
            models.Index(fields=["exported_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.observed_account_name} on {self.asset_id} at {self.occurred_at:%Y-%m-%d %H:%M}"

    @property
    def duration_seconds(self) -> int | None:
        if not self.ended_at:
            return None
        return int((self.ended_at - self.occurred_at).total_seconds())

    @property
    def is_certain(self) -> bool:
        """Tiers one and two. Tier three is inference and should be read as such."""
        return self.mechanism in (
            self.Mechanism.BROKERED_SESSION,
            self.Mechanism.APPLICATION_FETCH,
        )


class CredentialAssetLink(models.Model):
    """
    Rolled-up reach: this credential has been seen logging in to this asset.

    Maintained by the correlation pass so the blast-radius question -- what does
    this one credential open -- is a single indexed read rather than an
    aggregate over the whole observation table.
    """

    account = models.ForeignKey(ManagedAccount, on_delete=models.CASCADE, related_name="asset_links")
    asset = models.ForeignKey(TargetAsset, on_delete=models.CASCADE, related_name="account_links")
    first_seen_at = models.DateTimeField()
    last_seen_at = models.DateTimeField()
    observation_count = models.PositiveIntegerField(default=0)
    unexplained_count = models.PositiveIntegerField(default=0)
    mechanisms = models.JSONField(default=list, blank=True)
    #: True when the asset is not the one the vault has the account mapped to.
    outside_mapped_scope = models.BooleanField(default=False)

    class Meta:
        unique_together = [("account", "asset")]
        ordering = ["-last_seen_at"]
        indexes = [models.Index(fields=["account", "-last_seen_at"])]
