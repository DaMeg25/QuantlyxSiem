"""
Who may reach which resource, on whose authority, and until when.

One decision shapes this whole module: **this system records approvals; it does
not grant access.** Provisioning is handed to whatever already owns it -- the
source control platform, the identity governance suite, a change ticket. There
are three reasons, and they are worth being able to recite in a design review:

  1. A monitoring system that can also grant is a monitoring system whose
     compromise grants. Everything else here is read-only by construction, and
     that property is worth more than the convenience of a provision button.
  2. The platforms already have provisioning, with their own controls and their
     own audit. Duplicating it means two sources of truth about who has access,
     and the disagreement between them is discovered during an incident.
  3. What is actually missing in most estates is not a provisioning mechanism.
     It is the record of *why* someone has access, whether it was ever approved,
     and whether it was removed when it was supposed to be. That is a recording
     and reconciliation problem, and it is what this module solves.

So the flow is: request, policy, approvals, handoff, then reconciliation against
what the resource actually reports. The last step is the one that finds
everything interesting -- access that exists with no approval behind it, and
grants that expired on paper and not in reality.
"""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone


class ResourcePlatform(models.TextChoices):
    GITHUB = "github", "GitHub"
    GITHUB_ENTERPRISE = "github_enterprise", "GitHub Enterprise"
    GITLAB = "gitlab", "GitLab"
    BITBUCKET = "bitbucket", "Bitbucket"
    AZURE_DEVOPS = "azure_devops", "Azure DevOps"
    ARTIFACT_REGISTRY = "artifact_registry", "Artifact registry"
    CI_PIPELINE = "ci_pipeline", "Continuous integration pipeline"
    CLOUD_ACCOUNT = "cloud_account", "Cloud account"
    NETWORK_GROUP = "network_group", "Network device group"
    DATABASE = "database", "Database"
    OTHER = "other", "Other"


class Criticality(models.TextChoices):
    CRITICAL = "critical", "Critical"
    HIGH = "high", "High"
    MODERATE = "moderate", "Moderate"
    LOW = "low", "Low"


class PrincipalType(models.TextChoices):
    DEVELOPER = "developer", "Developer"
    ENGINEER = "engineer", "Engineer"
    BOT = "bot", "Bot or automation identity"
    SERVICE = "service", "Service identity"
    VENDOR = "vendor", "Third party"
    UNKNOWN = "unknown", "Unclassified"


NON_HUMAN_PRINCIPALS = [PrincipalType.BOT, PrincipalType.SERVICE]


class Resource(models.Model):
    """A repository, project, pipeline, registry, or anything else access is granted to."""

    platform = models.CharField(max_length=24, choices=ResourcePlatform.choices)
    #: Stable platform identifier: "org/repo", a project path, an account number.
    identifier = models.CharField(max_length=300)
    display_name = models.CharField(max_length=300, blank=True)
    url = models.URLField(blank=True)

    criticality = models.CharField(max_length=12, choices=Criticality.choices, default=Criticality.MODERATE)
    #: Whether the resource can reach production. Drives which policy applies
    #: and how hard the rules push on standing access.
    production = models.BooleanField(default=False)
    data_classification = models.CharField(max_length=40, blank=True)

    owner_identity = models.CharField(max_length=200, blank=True)
    owner_team = models.CharField(max_length=120, blank=True)
    business_application = models.CharField(max_length=200, blank=True)

    archived = models.BooleanField(default=False)
    first_seen_at = models.DateTimeField(default=timezone.now)
    last_reconciled_at = models.DateTimeField(null=True, blank=True)
    detail = models.JSONField(default=dict, blank=True)

    class Meta:
        unique_together = [("platform", "identifier")]
        ordering = ["platform", "identifier"]
        indexes = [
            models.Index(fields=["platform", "production"]),
            models.Index(fields=["criticality"]),
        ]

    def __str__(self) -> str:
        return f"{self.get_platform_display()}:{self.identifier}"

    @property
    def reconciliation_stale(self) -> bool:
        if not self.last_reconciled_at:
            return True
        return timezone.now() - self.last_reconciled_at > timedelta(days=2)


class Principal(models.Model):
    """
    Someone or something that holds access.

    Bots are first-class here rather than an afterthought, because they are the
    population that accumulates standing write access to production and never
    appears in a recertification campaign aimed at people.
    """

    identifier = models.CharField(max_length=200, unique=True)
    display_name = models.CharField(max_length=200, blank=True)
    principal_type = models.CharField(
        max_length=16, choices=PrincipalType.choices, default=PrincipalType.UNKNOWN
    )
    email = models.CharField(max_length=200, blank=True)
    team = models.CharField(max_length=120, blank=True)

    #: Every non-human principal needs a named human who answers for it.
    responsible_owner = models.CharField(max_length=200, blank=True)
    #: The vaulted credential this bot authenticates with, when there is one.
    #: This is the join that makes "bot with write access to production and a
    #: credential that has never been rotated" a single query.
    managed_account = models.ForeignKey(
        "inventory.ManagedAccount",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="principals",
    )

    active = models.BooleanField(default=True)
    first_seen_at = models.DateTimeField(default=timezone.now)
    last_seen_at = models.DateTimeField(default=timezone.now)
    detail = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["identifier"]
        indexes = [models.Index(fields=["principal_type", "active"])]

    def __str__(self) -> str:
        return self.display_name or self.identifier

    @property
    def is_non_human(self) -> bool:
        return self.principal_type in {value for value in NON_HUMAN_PRINCIPALS}


class AccessLevel(models.TextChoices):
    READ = "read", "Read"
    TRIAGE = "triage", "Triage"
    WRITE = "write", "Write"
    MAINTAIN = "maintain", "Maintain"
    ADMIN = "admin", "Administer"
    DEPLOY = "deploy", "Deploy to production"


ELEVATED_LEVELS = [AccessLevel.WRITE, AccessLevel.MAINTAIN, AccessLevel.ADMIN, AccessLevel.DEPLOY]


class ApprovalPolicy(models.Model):
    """
    How much authority a given kind of access needs, and for how long it may run.

    Policies are matched most specific first: a policy naming the resource beats
    one naming the platform, which beats the catch-all. That ordering is the
    whole point -- one repository can need two approvals and a fourteen-day
    ceiling while the rest of the estate needs one and thirty.
    """

    name = models.CharField(max_length=120, unique=True)
    resource = models.ForeignKey(
        Resource, on_delete=models.CASCADE, null=True, blank=True, related_name="policies"
    )
    platform = models.CharField(max_length=24, choices=ResourcePlatform.choices, blank=True)
    applies_to_production_only = models.BooleanField(default=False)
    minimum_criticality = models.CharField(max_length=12, choices=Criticality.choices, blank=True)
    access_levels = models.JSONField(default=list, blank=True)
    principal_types = models.JSONField(default=list, blank=True)

    approvals_required = models.PositiveSmallIntegerField(default=1)
    #: Groups entitled to approve, evaluated against Approver.groups.
    approver_groups = models.JSONField(default=list, blank=True)
    #: The resource owner must be one of the approvers regardless of group.
    require_resource_owner = models.BooleanField(default=False)
    require_ticket_reference = models.BooleanField(default=True)
    require_justification = models.BooleanField(default=True)

    maximum_duration_days = models.PositiveIntegerField(default=30)
    #: Standing access is access with no expiry. Off by default everywhere, and
    #: the rules treat any exception as a finding worth reviewing.
    standing_access_allowed = models.BooleanField(default=False)
    #: A non-human principal must name a responsible human before it can hold
    #: access under this policy.
    require_owner_for_bots = models.BooleanField(default=True)

    enabled = models.BooleanField(default=True)
    notes = models.TextField(blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        verbose_name_plural = "approval policies"

    def __str__(self) -> str:
        return self.name

    @property
    def specificity(self) -> int:
        score = 0
        if self.resource_id:
            score += 8
        if self.platform:
            score += 4
        if self.access_levels:
            score += 2
        if self.principal_types:
            score += 1
        return score


class Approver(models.Model):
    """Someone entitled to approve, and what they are entitled to approve."""

    identifier = models.CharField(max_length=200, unique=True)
    display_name = models.CharField(max_length=200, blank=True)
    groups = models.JSONField(default=list, blank=True)
    active = models.BooleanField(default=True)
    #: An approver who cannot approve their own team's requests. Set for anyone
    #: whose independence the control depends on.
    independent = models.BooleanField(default=False)
    team = models.CharField(max_length=120, blank=True)

    class Meta:
        ordering = ["identifier"]

    def __str__(self) -> str:
        return self.display_name or self.identifier


class AccessRequest(models.Model):
    """One request for one principal to hold one level of access on one resource."""

    class State(models.TextChoices):
        DRAFT = "draft", "Draft"
        PENDING = "pending", "Pending approval"
        APPROVED = "approved", "Approved, awaiting provisioning"
        PROVISIONED = "provisioned", "Provisioned"
        REJECTED = "rejected", "Rejected"
        WITHDRAWN = "withdrawn", "Withdrawn"
        EXPIRED = "expired", "Expired"
        REVOKED = "revoked", "Revoked"

    reference = models.CharField(max_length=32, unique=True)
    principal = models.ForeignKey(Principal, on_delete=models.PROTECT, related_name="requests")
    resource = models.ForeignKey(Resource, on_delete=models.PROTECT, related_name="requests")
    access_level = models.CharField(max_length=12, choices=AccessLevel.choices)

    requested_by = models.CharField(max_length=200)
    justification = models.TextField(blank=True)
    ticket_reference = models.CharField(max_length=80, blank=True)
    requested_days = models.PositiveIntegerField(null=True, blank=True)

    policy = models.ForeignKey(
        ApprovalPolicy, on_delete=models.SET_NULL, null=True, blank=True, related_name="requests"
    )
    approvals_required = models.PositiveSmallIntegerField(default=1)

    state = models.CharField(max_length=16, choices=State.choices, default=State.DRAFT)
    created_at = models.DateTimeField(default=timezone.now)
    decided_at = models.DateTimeField(null=True, blank=True)
    provisioned_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    decision_note = models.TextField(blank=True)

    #: The task raised in whatever actually performs provisioning. This system
    #: records that the handoff happened; it does not perform the change.
    handoff_reference = models.CharField(max_length=120, blank=True)
    handoff_system = models.CharField(max_length=80, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["state", "-created_at"]),
            models.Index(fields=["expires_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.reference} {self.principal_id} -> {self.resource_id} ({self.access_level})"

    @property
    def approvals_recorded(self) -> int:
        return self.approvals.filter(decision=ApprovalStep.Decision.APPROVED).count()

    @property
    def is_open(self) -> bool:
        return self.state in (self.State.DRAFT, self.State.PENDING, self.State.APPROVED)

    @property
    def age_days(self) -> int:
        return (timezone.now() - self.created_at).days


class ApprovalStep(models.Model):
    """
    One recorded decision, chained to the one before it.

    The chain is the point. An approval record that can be edited afterwards is
    not evidence of anything, so each step carries a hash over its own content
    and the previous step's hash. Altering a decision after the fact breaks
    every link after it, and `verify_chain` says where.
    """

    class Decision(models.TextChoices):
        APPROVED = "approved", "Approved"
        REJECTED = "rejected", "Rejected"
        ABSTAINED = "abstained", "Abstained"

    request = models.ForeignKey(AccessRequest, on_delete=models.CASCADE, related_name="approvals")
    sequence = models.PositiveSmallIntegerField()
    approver_identity = models.CharField(max_length=200)
    approver_groups = models.JSONField(default=list, blank=True)
    decision = models.CharField(max_length=12, choices=Decision.choices)
    comment = models.TextField(blank=True)
    decided_at = models.DateTimeField(default=timezone.now)
    source_address = models.CharField(max_length=64, blank=True)

    previous_hash = models.CharField(max_length=64, blank=True)
    content_hash = models.CharField(max_length=64, blank=True)

    class Meta:
        unique_together = [("request", "sequence")]
        ordering = ["request", "sequence"]

    def compute_hash(self) -> str:
        payload = json.dumps(
            {
                "request": self.request_id,
                "sequence": self.sequence,
                "approver": self.approver_identity,
                "decision": self.decision,
                "comment": self.comment,
                "decided_at": self.decided_at.isoformat(),
                "previous": self.previous_hash,
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def save(self, *args, **kwargs):
        if not self.content_hash:
            self.content_hash = self.compute_hash()
        super().save(*args, **kwargs)


class AccessGrant(models.Model):
    """
    Effective access: what a principal actually holds on a resource right now.

    Two origins, and the difference between them is the whole reconciliation
    story. A grant traced to an approved request is governed. A grant discovered
    on the platform with no request behind it is not, however legitimate it may
    turn out to be.
    """

    class Origin(models.TextChoices):
        APPROVED = "approved", "From an approved request"
        DISCOVERED = "discovered", "Found on the platform, no request behind it"
        IMPORTED = "imported", "Imported at onboarding"
        BREAK_GLASS = "break_glass", "Emergency, approved after the fact"

    principal = models.ForeignKey(Principal, on_delete=models.CASCADE, related_name="grants")
    resource = models.ForeignKey(Resource, on_delete=models.CASCADE, related_name="grants")
    access_level = models.CharField(max_length=12, choices=AccessLevel.choices)
    origin = models.CharField(max_length=16, choices=Origin.choices, default=Origin.DISCOVERED)
    request = models.ForeignKey(
        AccessRequest, on_delete=models.SET_NULL, null=True, blank=True, related_name="grants"
    )

    granted_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    #: Last time the platform confirmed this access still exists.
    last_confirmed_at = models.DateTimeField(default=timezone.now)
    #: Set when the platform no longer reports it, which is how expiry is
    #: verified rather than assumed.
    absent_since = models.DateTimeField(null=True, blank=True)

    last_used_at = models.DateTimeField(null=True, blank=True)
    detail = models.JSONField(default=dict, blank=True)

    class Meta:
        unique_together = [("principal", "resource", "access_level")]
        ordering = ["resource", "principal"]
        indexes = [
            models.Index(fields=["origin"]),
            models.Index(fields=["expires_at"]),
            models.Index(fields=["revoked_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.principal_id} {self.access_level} on {self.resource_id}"

    @property
    def active(self) -> bool:
        return self.revoked_at is None and self.absent_since is None

    @property
    def standing(self) -> bool:
        return self.active and self.expires_at is None

    @property
    def overdue_days(self) -> int | None:
        if not self.expires_at or not self.active:
            return None
        delta = (timezone.now() - self.expires_at).days
        return delta if delta > 0 else 0

    @property
    def elevated(self) -> bool:
        return self.access_level in {level.value for level in ELEVATED_LEVELS}


class AccessReview(models.Model):
    """A recertification campaign over a set of grants."""

    class State(models.TextChoices):
        OPEN = "open", "Open"
        CLOSED = "closed", "Closed"

    name = models.CharField(max_length=160, unique=True)
    opened_at = models.DateTimeField(default=timezone.now)
    due_at = models.DateTimeField(null=True, blank=True)
    closed_at = models.DateTimeField(null=True, blank=True)
    state = models.CharField(max_length=12, choices=State.choices, default=State.OPEN)
    scope = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-opened_at"]

    def __str__(self) -> str:
        return self.name


class AccessReviewItem(models.Model):
    class Decision(models.TextChoices):
        PENDING = "pending", "Pending"
        RETAIN = "retain", "Retain"
        REVOKE = "revoke", "Revoke"
        MODIFY = "modify", "Reduce"

    review = models.ForeignKey(AccessReview, on_delete=models.CASCADE, related_name="items")
    grant = models.ForeignKey(AccessGrant, on_delete=models.CASCADE, related_name="review_items")
    reviewer_identity = models.CharField(max_length=200, blank=True)
    decision = models.CharField(max_length=12, choices=Decision.choices, default=Decision.PENDING)
    decided_at = models.DateTimeField(null=True, blank=True)
    comment = models.TextField(blank=True)

    class Meta:
        unique_together = [("review", "grant")]
        ordering = ["review", "grant"]


def max_grant_days() -> int:
    return int(getattr(settings, "ACCESS_MAX_GRANT_DAYS", 90))


def default_grant_days() -> int:
    return int(getattr(settings, "ACCESS_DEFAULT_GRANT_DAYS", 30))
