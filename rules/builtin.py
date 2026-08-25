"""
Detections shipped with the platform.

Grouping follows the questions an examiner asks:
  ROT  Is every privileged credential being changed on schedule?
  BOT  Are non-human credentials governed as strictly as human ones?
  OWN  Does every credential have an accountable human?
  USE  Is the credential still needed, and is it being used normally?
  ONB  Is anything privileged living outside the vault?
  SOD  Can a specific action be attributed to a specific person?

Each rule states its own parameters so a deployment can tune thresholds in
RuleConfiguration rather than in code.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Iterator

from django.db.models import Count, Q
from django.utils import timezone

from connectors.base import Capability
from inventory.models import (
    AccountKind,
    AccountStatus,
    DiscoveredAccount,
    LifecycleEvent,
    ManagedAccount,
    NON_HUMAN_KINDS,
    Severity,
)

from .engine import Candidate, Rule, register


@register
class RotationOverdue(Rule):
    rule_id = "ROT-001"
    title = "Credential rotation is past its policy interval"
    category = "rotation"
    severity = Severity.HIGH
    defaults = {"grace_days": 3, "critical_multiple": 2.0, "fallback_interval_days": 90}

    def evaluate(self) -> Iterator[Candidate]:
        now = timezone.now()
        grace = timedelta(days=self.parameter("grace_days"))
        fallback = self.parameter("fallback_interval_days")

        for account in self.base_queryset().filter(status=AccountStatus.ACTIVE):
            interval = account.rotation_interval_days or fallback
            if account.last_rotation_at is None:
                due = (account.onboarded_at or account.first_seen_at) + timedelta(days=interval)
            else:
                due = account.next_rotation_due or account.last_rotation_at + timedelta(days=interval)
            if now <= due + grace:
                continue

            overdue_days = (now - due).days
            severity = (
                Severity.CRITICAL
                if overdue_days > interval * self.parameter("critical_multiple")
                else self.effective_severity
            )
            yield Candidate(
                account=account,
                severity_override=severity,
                evidence={
                    "policy_interval_days": interval,
                    "last_rotation": account.last_rotation_at.isoformat()
                    if account.last_rotation_at
                    else "never",
                    "due": due.isoformat(),
                    "overdue_days": overdue_days,
                    "credential_age_days": account.credential_age_days,
                },
            )

    def describe(self, candidate: Candidate) -> str:
        return f"Rotation overdue by {candidate.evidence['overdue_days']} days"


@register
class RotationFailing(Rule):
    rule_id = "ROT-002"
    title = "Automatic rotation is failing repeatedly"
    category = "rotation"
    severity = Severity.CRITICAL
    defaults = {"failure_threshold": 2}

    def evaluate(self) -> Iterator[Candidate]:
        threshold = self.parameter("failure_threshold")
        queryset = self.base_queryset().filter(
            consecutive_rotation_failures__gte=threshold
        )
        for account in queryset:
            yield Candidate(
                account=account,
                evidence={
                    "consecutive_failures": account.consecutive_rotation_failures,
                    "reason": account.rotation_failure_reason,
                    "last_successful_rotation": account.last_rotation_at.isoformat()
                    if account.last_rotation_at
                    else "never",
                },
            )


@register
class VaultOutOfSync(Rule):
    rule_id = "ROT-003"
    title = "Vault copy no longer matches the target system"
    category = "rotation"
    severity = Severity.HIGH
    requires = frozenset({Capability.ACCOUNTS, Capability.VERIFICATION})

    def evaluate(self) -> Iterator[Candidate]:
        for account in self.base_queryset().filter(verification_ok=False):
            yield Candidate(
                account=account,
                evidence={
                    "last_verification": account.last_verification_at.isoformat()
                    if account.last_verification_at
                    else "never",
                    "impact": "A break-glass retrieval from this vault would fail on the target",
                },
            )


@register
class NonHumanRotationDisabled(Rule):
    rule_id = "BOT-001"
    title = "Non-human account has automatic rotation switched off"
    category = "non_human"
    severity = Severity.HIGH

    def evaluate(self) -> Iterator[Candidate]:
        queryset = self.base_queryset().filter(
            kind__in=NON_HUMAN_KINDS,
            auto_rotation_enabled=False,
            status=AccountStatus.ACTIVE,
        )
        for account in queryset:
            yield Candidate(
                account=account,
                evidence={
                    "kind": account.get_kind_display(),
                    "credential_age_days": account.credential_age_days,
                    "business_application": account.business_application,
                    "typical_cause": "Rotation disabled after an application outage and never re-enabled",
                },
            )


@register
class NonHumanNeverRotated(Rule):
    rule_id = "BOT-002"
    title = "Non-human credential has never been rotated"
    category = "non_human"
    severity = Severity.CRITICAL
    defaults = {"minimum_age_days": 30}

    def evaluate(self) -> Iterator[Candidate]:
        cutoff = timezone.now() - timedelta(days=self.parameter("minimum_age_days"))
        queryset = self.base_queryset().filter(
            kind__in=NON_HUMAN_KINDS,
            last_rotation_at__isnull=True,
            status=AccountStatus.ACTIVE,
        ).filter(Q(onboarded_at__lt=cutoff) | Q(onboarded_at__isnull=True, first_seen_at__lt=cutoff))
        for account in queryset:
            reference = account.onboarded_at or account.first_seen_at
            yield Candidate(
                account=account,
                evidence={
                    "known_since": reference.isoformat(),
                    "days_since_onboarding": (timezone.now() - reference).days,
                    "auto_rotation_enabled": account.auto_rotation_enabled,
                },
            )


@register
class NonHumanRotationDisabledRecently(Rule):
    rule_id = "BOT-003"
    title = "Automatic rotation was disabled on a non-human account"
    category = "non_human"
    severity = Severity.HIGH
    defaults = {"lookback_days": 7}

    def evaluate(self) -> Iterator[Candidate]:
        since = timezone.now() - timedelta(days=self.parameter("lookback_days"))
        recent = (
            LifecycleEvent.objects.filter(
                kind=LifecycleEvent.Kind.AUTO_ROTATION_DISABLED,
                occurred_at__gte=since,
                account__kind__in=NON_HUMAN_KINDS,
                account__system_id__in=self.supported_system_ids(),
            )
            .select_related("account", "account__system")
            .order_by("account_id", "-occurred_at")
        )
        seen: set[int] = set()
        for event in recent:
            if event.account_id in seen:
                continue
            seen.add(event.account_id)
            if event.account.auto_rotation_enabled:
                continue  # re-enabled since
            yield Candidate(
                account=event.account,
                evidence={
                    "changed_at": event.occurred_at.isoformat(),
                    "actor": event.actor or "unknown",
                    "detail": event.detail,
                },
            )


@register
class MissingOwner(Rule):
    rule_id = "OWN-001"
    title = "Privileged account has no recorded owner"
    category = "ownership"
    severity = Severity.MEDIUM
    requires = frozenset({Capability.ACCOUNTS, Capability.OWNERSHIP})

    def evaluate(self) -> Iterator[Candidate]:
        queryset = self.base_queryset().filter(
            Q(owner_identity="") & Q(owner_team=""),
            status=AccountStatus.ACTIVE,
        )
        for account in queryset:
            severity = Severity.HIGH if account.is_non_human else self.effective_severity
            yield Candidate(
                account=account,
                severity_override=severity,
                evidence={
                    "kind": account.get_kind_display(),
                    "container": account.container,
                    "consequence": "No one can attest to this account at recertification",
                },
            )


@register
class OwnerDeparted(Rule):
    rule_id = "OWN-002"
    title = "Recorded owner is no longer an active identity"
    category = "ownership"
    severity = Severity.HIGH
    requires = frozenset({Capability.ACCOUNTS, Capability.OWNERSHIP})
    defaults = {"active_identity_source": "identity_feed"}

    def evaluate(self) -> Iterator[Candidate]:
        """
        Requires a populated identity feed. Load the active-worker list into the
        cache key "active_identities" from your identity governance platform;
        without it the rule is inert rather than noisy.
        """
        from django.core.cache import cache

        active = cache.get("active_identities")
        if not active:
            return
        active_set = {value.lower() for value in active}
        queryset = self.base_queryset().exclude(owner_identity="")
        for account in queryset:
            if account.owner_identity.lower() in active_set:
                continue
            yield Candidate(
                account=account,
                evidence={
                    "owner": account.owner_identity,
                    "checked_against": self.parameter("active_identity_source"),
                },
            )


@register
class DormantPrivilegedAccount(Rule):
    rule_id = "USE-001"
    title = "Active privileged account has not been used"
    category = "usage"
    severity = Severity.MEDIUM
    requires = frozenset({Capability.ACCOUNTS, Capability.USAGE_TIMESTAMPS})
    defaults = {"dormant_days": 90}

    def evaluate(self) -> Iterator[Candidate]:
        cutoff = timezone.now() - timedelta(days=self.parameter("dormant_days"))
        queryset = self.base_queryset().filter(
            status=AccountStatus.ACTIVE,
            last_used_at__lt=cutoff,
        )
        for account in queryset:
            yield Candidate(
                account=account,
                evidence={
                    "last_used": account.last_used_at.isoformat(),
                    "dormant_days": account.dormant_days,
                    "recommended_action": "Disable, then remove after the agreed grace period",
                },
            )


@register
class BreakGlassUsedWithoutTicket(Rule):
    rule_id = "USE-002"
    title = "Break-glass credential retrieved without a ticket reference"
    category = "usage"
    severity = Severity.CRITICAL
    requires = frozenset({Capability.ACCOUNTS, Capability.ACTIVITY, Capability.TICKET_REFERENCE})
    defaults = {"lookback_days": 30}

    def evaluate(self) -> Iterator[Candidate]:
        since = timezone.now() - timedelta(days=self.parameter("lookback_days"))
        events = (
            LifecycleEvent.objects.filter(
                kind=LifecycleEvent.Kind.CHECKED_OUT,
                occurred_at__gte=since,
                ticket_reference="",
                account__kind=AccountKind.BREAK_GLASS,
                account__system_id__in=self.supported_system_ids(),
            )
            .select_related("account", "account__system")
        )
        grouped: dict[int, list[LifecycleEvent]] = {}
        for event in events:
            grouped.setdefault(event.account_id, []).append(event)
        for account_id, account_events in grouped.items():
            account = account_events[0].account
            yield Candidate(
                account=account,
                evidence={
                    "retrievals": len(account_events),
                    "actors": sorted({e.actor for e in account_events if e.actor}),
                    "most_recent": max(e.occurred_at for e in account_events).isoformat(),
                },
            )


@register
class UnusualRetrievalVolume(Rule):
    rule_id = "USE-003"
    title = "Credential retrieval volume is far above this account's baseline"
    category = "usage"
    severity = Severity.HIGH
    requires = frozenset({Capability.ACCOUNTS, Capability.ACTIVITY})
    defaults = {"window_days": 1, "baseline_days": 30, "multiple": 5, "minimum_events": 5}

    def evaluate(self) -> Iterator[Candidate]:
        now = timezone.now()
        window = now - timedelta(days=self.parameter("window_days"))
        baseline_start = now - timedelta(days=self.parameter("baseline_days"))
        multiple = self.parameter("multiple")
        minimum = self.parameter("minimum_events")

        recent = (
            LifecycleEvent.objects.filter(
                kind=LifecycleEvent.Kind.CHECKED_OUT,
                occurred_at__gte=window,
                account__system_id__in=self.supported_system_ids(),
            )
            .values("account_id")
            .annotate(count=Count("id"))
        )
        baseline = {
            row["account_id"]: row["count"]
            for row in LifecycleEvent.objects.filter(
                kind=LifecycleEvent.Kind.CHECKED_OUT,
                occurred_at__gte=baseline_start,
                occurred_at__lt=window,
            )
            .values("account_id")
            .annotate(count=Count("id"))
        }
        baseline_days = self.parameter("baseline_days") - self.parameter("window_days")

        for row in recent:
            count = row["count"]
            if count < minimum:
                continue
            daily_average = baseline.get(row["account_id"], 0) / max(baseline_days, 1)
            expected = max(daily_average * self.parameter("window_days"), 0.5)
            if count < expected * multiple:
                continue
            account = ManagedAccount.objects.select_related("system").get(pk=row["account_id"])
            yield Candidate(
                account=account,
                evidence={
                    "retrievals_in_window": count,
                    "baseline_daily_average": round(daily_average, 2),
                    "multiple_over_baseline": round(count / expected, 1),
                },
            )


@register
class PrivilegedAccountOutsideVault(Rule):
    rule_id = "ONB-001"
    title = "Privileged account discovered on a target but not vaulted"
    category = "onboarding"
    severity = Severity.HIGH
    defaults = {"minimum_age_days": 7}

    def evaluate(self) -> Iterator[Candidate]:
        """
        This rule reports against a synthetic placeholder account per target so
        that findings stay in one table. Discovery data comes from the vendor's
        own scanner or a separate sweep loaded into DiscoveredAccount.
        """
        cutoff = timezone.now() - timedelta(days=self.parameter("minimum_age_days"))
        pending = DiscoveredAccount.objects.filter(
            onboarded=False, matched_account__isnull=True, discovered_at__lt=cutoff
        )
        for discovery in pending:
            match = ManagedAccount.objects.filter(
                username__iexact=discovery.username,
                target_address__iexact=discovery.target_address,
            ).select_related("system").first()
            if match:
                discovery.matched_account = match
                discovery.onboarded = True
                discovery.save(update_fields=["matched_account", "onboarded"])
                continue
            anchor = ManagedAccount.objects.filter(
                target_address__iexact=discovery.target_address
            ).select_related("system").first()
            if anchor is None:
                continue  # nothing to attach the finding to; report through the gap widget instead
            yield Candidate(
                account=anchor,
                evidence={
                    "unvaulted_username": discovery.username,
                    "target": discovery.target_address,
                    "privilege_level": discovery.privilege_level,
                    "discovered_at": discovery.discovered_at.isoformat(),
                    "source": discovery.source,
                },
                subject_key=f"{discovery.username}@{discovery.target_address}",
            )


@register
class SharedHumanAccount(Rule):
    rule_id = "SOD-001"
    title = "Human administrator account is shared without exclusive checkout"
    category = "attribution"
    severity = Severity.MEDIUM
    requires = frozenset({Capability.ACCOUNTS, Capability.ENTITLEMENTS})
    defaults = {"entitlement_threshold": 2}

    def evaluate(self) -> Iterator[Candidate]:
        threshold = self.parameter("entitlement_threshold")
        queryset = self.base_queryset().filter(
            kind=AccountKind.HUMAN,
            exclusive_checkout=False,
            status=AccountStatus.ACTIVE,
            entitled_identity_count__gte=threshold,
        )
        for account in queryset:
            yield Candidate(
                account=account,
                evidence={
                    "entitled_identities": account.entitled_identity_count,
                    "consequence": "Actions taken with this account cannot be attributed to one person",
                },
            )


@register
class StalePendingDeletion(Rule):
    rule_id = "DEL-001"
    title = "Account has sat in pending deletion past the grace window"
    category = "decommission"
    severity = Severity.LOW
    defaults = {"grace_days": 30}

    def evaluate(self) -> Iterator[Candidate]:
        cutoff = timezone.now() - timedelta(days=self.parameter("grace_days"))
        queryset = self.base_queryset().filter(
            status=AccountStatus.PENDING_DELETE, last_seen_at__lt=cutoff
        )
        for account in queryset:
            yield Candidate(
                account=account,
                evidence={"pending_since": account.last_seen_at.isoformat()},
            )


@register
class CollectionStale(Rule):
    rule_id = "OPS-001"
    title = "Collection from this platform has stopped"
    category = "operations"
    severity = Severity.HIGH

    def evaluate(self) -> Iterator[Candidate]:
        """
        Blind spots are findings too. If the collector cannot reach a platform,
        every other rule silently stops firing for it -- which looks identical
        to compliance.
        """
        from inventory.models import PamSystem

        for system in PamSystem.objects.filter(enabled=True):
            if not system.collection_overdue:
                continue
            anchor = ManagedAccount.objects.filter(system=system).select_related("system").first()
            if anchor is None:
                continue
            yield Candidate(
                account=anchor,
                evidence={
                    "platform": system.name,
                    "last_successful_collection": system.last_successful_collection.isoformat()
                    if system.last_successful_collection
                    else "never",
                    "expected_interval_minutes": system.collection_interval_minutes,
                    "consequence": "All detections for this platform are currently blind",
                },
                subject_key=system.name,
            )


# ==========================================================================
# Where credentials were actually used
#
# These read UsageObservation rather than the vault inventory. The first one is
# the reason the whole correlation pass exists.
# ==========================================================================


@register
class AuthenticationWithoutRetrieval(Rule):
    rule_id = "USE-004"
    title = "Privileged login with no vault retrieval behind it"
    category = "usage"
    severity = Severity.CRITICAL
    requires = frozenset({Capability.ACCOUNTS})
    defaults = {"lookback_days": 14, "minimum_events": 1, "ignore_mechanisms": []}

    def evaluate(self) -> Iterator[Candidate]:
        """
        A managed privileged credential authenticated on a target, and no
        checkout from the vault accounts for it. The plain reading is that a
        working copy of that credential exists outside the vault -- in a script,
        a runbook, a saved session, someone's password manager.

        This is the finding no vault can produce on its own, because the vault
        genuinely did not see the event. It requires at least one target-side
        telemetry feed; without one the rule is inert and the coverage page says
        so rather than reporting silence as compliance.
        """
        from inventory.models import TelemetrySource, UsageObservation

        if not TelemetrySource.objects.filter(enabled=True).exists():
            return

        since = timezone.now() - timedelta(days=self.parameter("lookback_days"))
        ignore = set(self.parameter("ignore_mechanisms") or [])
        observations = (
            UsageObservation.objects.filter(
                correlation=UsageObservation.Correlation.UNEXPLAINED,
                occurred_at__gte=since,
                outcome="success",
                account__isnull=False,
            )
            .exclude(mechanism__in=ignore)
            .select_related("account", "account__system", "asset", "source")
        )

        grouped: dict[int, list] = {}
        for observation in observations:
            grouped.setdefault(observation.account_id, []).append(observation)

        minimum = self.parameter("minimum_events")
        exempt = set(self.configuration.exempt_account_ids) if self.configuration else set()

        for account_id, rows in grouped.items():
            if len(rows) < minimum or account_id in exempt:
                continue
            account = rows[0].account
            assets = sorted({row.asset.identifier for row in rows})
            yield Candidate(
                account=account,
                evidence={
                    "unexplained_logins": len(rows),
                    "assets": assets[:8],
                    "distinct_assets": len(assets),
                    "most_recent": max(row.occurred_at for row in rows).isoformat(),
                    "source_addresses": sorted({row.source_address for row in rows if row.source_address})[:5],
                    "telemetry": sorted({row.source.name for row in rows if row.source}),
                    "reading": "A usable copy of this credential exists outside the vault",
                },
            )

    def describe(self, candidate: Candidate) -> str:
        return (
            f"{candidate.evidence['unexplained_logins']} logins on "
            f"{candidate.evidence['distinct_assets']} assets with no vault retrieval"
        )


@register
class UsedOutsideMappedScope(Rule):
    rule_id = "USE-005"
    title = "Credential used on assets beyond the one it is mapped to"
    category = "usage"
    severity = Severity.HIGH
    requires = frozenset({Capability.ACCOUNTS})
    defaults = {"asset_threshold": 3, "lookback_days": 30}

    def evaluate(self) -> Iterator[Candidate]:
        """
        The vault has this account mapped to one target. It has been observed
        logging in to several. Either the mapping is wrong, which makes the
        rotation scope wrong, or the credential is shared across systems, which
        makes its blast radius larger than anyone has signed off.
        """
        from inventory.models import CredentialAssetLink

        threshold = self.parameter("asset_threshold")
        since = timezone.now() - timedelta(days=self.parameter("lookback_days"))
        links = (
            CredentialAssetLink.objects.filter(outside_mapped_scope=True, last_seen_at__gte=since)
            .select_related("account", "account__system", "asset")
        )
        grouped: dict[int, list] = {}
        for link in links:
            grouped.setdefault(link.account_id, []).append(link)

        for account_id, rows in grouped.items():
            if len(rows) < threshold:
                continue
            account = rows[0].account
            if account.status != AccountStatus.ACTIVE:
                continue
            yield Candidate(
                account=account,
                evidence={
                    "mapped_target": account.target_address or "unspecified",
                    "also_seen_on": sorted(link.asset.identifier for link in rows)[:10],
                    "asset_count": len(rows) + 1,
                    "consequence": "Rotating this credential affects every one of these systems",
                },
            )

    def describe(self, candidate: Candidate) -> str:
        return f"Credential reaches {candidate.evidence['asset_count']} assets, mapped to one"


@register
class RetrievedButNeverUsed(Rule):
    rule_id = "USE-006"
    title = "Credential retrieved and never used"
    category = "usage"
    severity = Severity.MEDIUM
    requires = frozenset({Capability.ACCOUNTS, Capability.ACTIVITY})
    defaults = {"lookback_days": 14, "settle_hours": 8, "minimum_events": 2}

    def evaluate(self) -> Iterator[Candidate]:
        """
        Usually benign: a check that failed, a change that was called off.
        Occasionally it is a credential being collected rather than used, which
        is what the early stage of an incident looks like from here.
        """
        from inventory.models import TelemetrySource, UsageObservation

        if not TelemetrySource.objects.filter(enabled=True).exists():
            return

        now = timezone.now()
        since = now - timedelta(days=self.parameter("lookback_days"))
        settled = now - timedelta(hours=self.parameter("settle_hours"))
        used_event_ids = set(
            UsageObservation.objects.filter(correlated_event__isnull=False).values_list(
                "correlated_event_id", flat=True
            )
        )
        retrievals = (
            LifecycleEvent.objects.filter(
                kind=LifecycleEvent.Kind.CHECKED_OUT,
                occurred_at__gte=since,
                occurred_at__lte=settled,
            )
            .exclude(pk__in=used_event_ids)
            .select_related("account", "account__system")
        )
        grouped: dict[int, list] = {}
        for event in retrievals:
            if event.account_id:
                grouped.setdefault(event.account_id, []).append(event)

        minimum = self.parameter("minimum_events")
        for account_id, rows in grouped.items():
            if len(rows) < minimum:
                continue
            yield Candidate(
                account=rows[0].account,
                evidence={
                    "retrievals_without_a_login": len(rows),
                    "actors": sorted({row.actor for row in rows if row.actor})[:5],
                    "most_recent": max(row.occurred_at for row in rows).isoformat(),
                    "note": "Benign in most cases; worth a look when the same person repeats it",
                },
            )


@register
class ExcessiveBlastRadius(Rule):
    rule_id = "USE-007"
    title = "One credential opens an unusually large number of systems"
    category = "usage"
    severity = Severity.HIGH
    requires = frozenset({Capability.ACCOUNTS})
    defaults = {"asset_threshold": 12, "lookback_days": 60}

    def evaluate(self) -> Iterator[Candidate]:
        from django.db.models import Count

        from inventory.models import CredentialAssetLink

        threshold = self.parameter("asset_threshold")
        since = timezone.now() - timedelta(days=self.parameter("lookback_days"))
        rows = (
            CredentialAssetLink.objects.filter(last_seen_at__gte=since)
            .values("account_id")
            .annotate(assets=Count("asset_id"))
            .filter(assets__gte=threshold)
        )
        for row in rows:
            account = (
                ManagedAccount.objects.live()
                .select_related("system")
                .filter(pk=row["account_id"], status=AccountStatus.ACTIVE)
                .first()
            )
            if account is None:
                continue
            links = CredentialAssetLink.objects.filter(account=account).select_related("asset")
            kinds = sorted({link.asset.asset_type for link in links})
            yield Candidate(
                account=account,
                evidence={
                    "asset_count": row["assets"],
                    "asset_types": kinds,
                    "sample": sorted(link.asset.identifier for link in links)[:10],
                    "consequence": (
                        "One compromised credential reaches all of these. Rotation is also "
                        "a change affecting every one of them, which is why nobody wants to do it."
                    ),
                },
            )

    def describe(self, candidate: Candidate) -> str:
        return f"Credential observed on {candidate.evidence['asset_count']} distinct systems"


@register
class TelemetryStale(Rule):
    rule_id = "OPS-002"
    title = "A target telemetry feed has stopped"
    category = "operations"
    severity = Severity.HIGH
    requires = frozenset({Capability.ACCOUNTS})

    def evaluate(self) -> Iterator[Candidate]:
        """
        The usage rules go quiet when a feed stops, and quiet reads as clean.
        Same failure mode as a stale platform, different input.
        """
        from inventory.models import TelemetrySource

        stale = [source for source in TelemetrySource.objects.filter(enabled=True) if source.stale]
        if not stale:
            return
        anchor = ManagedAccount.objects.live().select_related("system").first()
        if anchor is None:
            return
        for source in stale:
            yield Candidate(
                account=anchor,
                evidence={
                    "feed": source.name,
                    "kind": source.get_kind_display(),
                    "last_ingest": source.last_ingest_at.isoformat() if source.last_ingest_at else "never",
                    "consequence": "USE-004 and USE-006 cannot see anything this feed would have carried",
                },
                subject_key=source.name,
            )


# ==========================================================================
# Access approval
#
# The same shape as everything above: a record of what was authorised, a record
# of what is actually true, and findings in the gap between them.
# ==========================================================================


def _access_anchor():
    """
    Access findings attach to a managed account so they share one queue with the
    credential findings. Where a bot principal is linked to a vaulted credential
    that account is used, which puts the rotation finding and the access finding
    on the same row.
    """
    return ManagedAccount.objects.live().select_related("system").first()


@register
class UnapprovedAccess(Rule):
    rule_id = "ACC-001"
    title = "Access held with no approved request behind it"
    category = "access"
    severity = Severity.HIGH
    requires = frozenset({Capability.ACCOUNTS})
    defaults = {"elevated_only": True, "minimum_age_days": 3}

    def evaluate(self) -> Iterator[Candidate]:
        """
        The access is real. The authority for it is not recorded anywhere.

        This is the access-side twin of USE-004, and it is the finding that
        makes an approval workflow worth having: without reconciliation, a
        request form only proves that the people who used it followed the
        process.
        """
        from access.models import AccessGrant, ELEVATED_LEVELS, Resource

        if not Resource.objects.exists():
            return

        cutoff = timezone.now() - timedelta(days=self.parameter("minimum_age_days"))
        grants = AccessGrant.objects.filter(
            origin=AccessGrant.Origin.DISCOVERED,
            revoked_at__isnull=True,
            absent_since__isnull=True,
            granted_at__lt=cutoff,
        ).select_related("principal", "resource", "principal__managed_account")
        if self.parameter("elevated_only"):
            grants = grants.filter(access_level__in=[level.value for level in ELEVATED_LEVELS])

        anchor = _access_anchor()
        grouped: dict[int, list] = {}
        for grant in grants:
            grouped.setdefault(grant.principal_id, []).append(grant)

        for principal_id, rows in grouped.items():
            principal = rows[0].principal
            account = principal.managed_account or anchor
            if account is None:
                continue
            production = [row for row in rows if row.resource.production]
            yield Candidate(
                account=account,
                severity_override=Severity.CRITICAL if production else self.effective_severity,
                evidence={
                    "principal": principal.identifier,
                    "principal_type": principal.get_principal_type_display(),
                    "grants": len(rows),
                    "on_production": len(production),
                    "resources": sorted({f"{row.resource.identifier} ({row.access_level})" for row in rows})[:8],
                    "responsible_owner": principal.responsible_owner or "none recorded",
                },
                subject_key=principal.identifier,
            )

    def describe(self, candidate: Candidate) -> str:
        return (
            f"{candidate.evidence['principal']} holds {candidate.evidence['grants']} "
            "unapproved grants"
        )


@register
class ExpiredAccessStillPresent(Rule):
    rule_id = "ACC-002"
    title = "Access past its expiry is still live on the platform"
    category = "access"
    severity = Severity.CRITICAL
    requires = frozenset({Capability.ACCOUNTS})
    defaults = {"grace_days": 1}

    def evaluate(self) -> Iterator[Candidate]:
        """
        The closed-loop check. An approval that expires on paper and not in
        reality is worse than no expiry at all, because the register says the
        access is gone.
        """
        from access.reconcile import stale_expiries

        anchor = _access_anchor()
        grace = timedelta(days=self.parameter("grace_days"))
        for grant in stale_expiries():
            if timezone.now() - grant.expires_at < grace:
                continue
            account = grant.principal.managed_account or anchor
            if account is None:
                continue
            yield Candidate(
                account=account,
                evidence={
                    "principal": grant.principal.identifier,
                    "resource": grant.resource.identifier,
                    "access_level": grant.access_level,
                    "expired": grant.expires_at.isoformat(),
                    "days_overdue": grant.overdue_days,
                    "request": grant.request.reference if grant.request else "none",
                    "reading": "The register says this access ended; the platform disagrees",
                },
                subject_key=f"{grant.principal.identifier}:{grant.resource.identifier}:{grant.access_level}",
            )

    def describe(self, candidate: Candidate) -> str:
        return f"Access expired {candidate.evidence['days_overdue']} days ago and is still live"


@register
class BotAccessWithoutOwner(Rule):
    rule_id = "ACC-003"
    title = "Non-human identity holds elevated access with no responsible human"
    category = "access"
    severity = Severity.HIGH
    requires = frozenset({Capability.ACCOUNTS})

    def evaluate(self) -> Iterator[Candidate]:
        from access.models import AccessGrant, ELEVATED_LEVELS, NON_HUMAN_PRINCIPALS

        anchor = _access_anchor()
        grants = AccessGrant.objects.filter(
            revoked_at__isnull=True,
            absent_since__isnull=True,
            access_level__in=[level.value for level in ELEVATED_LEVELS],
            principal__principal_type__in=[value for value in NON_HUMAN_PRINCIPALS],
            principal__responsible_owner="",
        ).select_related("principal", "resource", "principal__managed_account")

        grouped: dict[int, list] = {}
        for grant in grants:
            grouped.setdefault(grant.principal_id, []).append(grant)

        for rows in grouped.values():
            principal = rows[0].principal
            account = principal.managed_account or anchor
            if account is None:
                continue
            yield Candidate(
                account=account,
                evidence={
                    "principal": principal.identifier,
                    "resources": sorted({row.resource.identifier for row in rows})[:8],
                    "levels": sorted({row.access_level for row in rows}),
                    "consequence": "Nobody can attest to this at recertification, so it survives every campaign",
                },
                subject_key=principal.identifier,
            )


@register
class SelfApprovedAccess(Rule):
    rule_id = "ACC-004"
    title = "Access approved by someone who should not have approved it"
    category = "access"
    severity = Severity.CRITICAL
    requires = frozenset({Capability.ACCOUNTS})

    def evaluate(self) -> Iterator[Candidate]:
        """
        The workflow refuses these at the point of decision, so anything found
        here arrived another way: an imported history, a direct database change,
        or a policy that was loosened after the fact. Worth knowing about either
        way.
        """
        from access.models import AccessRequest, ApprovalStep

        anchor = _access_anchor()
        if anchor is None:
            return
        for request in AccessRequest.objects.filter(
            state__in=[AccessRequest.State.APPROVED, AccessRequest.State.PROVISIONED]
        ).select_related("principal", "resource").prefetch_related("approvals"):
            approvers = {
                step.approver_identity.lower()
                for step in request.approvals.all()
                if step.decision == ApprovalStep.Decision.APPROVED
            }
            conflicts = approvers & {
                (request.requested_by or "").lower(),
                (request.principal.identifier or "").lower(),
                (request.principal.email or "").lower(),
            } - {""}
            insufficient = len(approvers) < request.approvals_required
            if not conflicts and not insufficient:
                continue
            yield Candidate(
                account=request.principal.managed_account or anchor,
                evidence={
                    "request": request.reference,
                    "principal": request.principal.identifier,
                    "resource": request.resource.identifier,
                    "self_approval_by": sorted(conflicts),
                    "approvals_recorded": len(approvers),
                    "approvals_required": request.approvals_required,
                },
                subject_key=request.reference,
            )


@register
class StandingProductionAccess(Rule):
    rule_id = "ACC-005"
    title = "Standing elevated access on a production resource"
    category = "access"
    severity = Severity.HIGH
    requires = frozenset({Capability.ACCOUNTS})
    defaults = {"production_only": True}

    def evaluate(self) -> Iterator[Candidate]:
        from access.reconcile import elevated_standing_access

        anchor = _access_anchor()
        grouped: dict[int, list] = {}
        for grant in elevated_standing_access(self.parameter("production_only")):
            grouped.setdefault(grant.principal_id, []).append(grant)

        for rows in grouped.values():
            principal = rows[0].principal
            account = principal.managed_account or anchor
            if account is None:
                continue
            yield Candidate(
                account=account,
                evidence={
                    "principal": principal.identifier,
                    "resources": sorted({row.resource.identifier for row in rows})[:8],
                    "levels": sorted({row.access_level for row in rows}),
                    "note": "No expiry recorded, so nothing will ever remove it without a decision",
                },
                subject_key=principal.identifier,
            )


@register
class BotWithUnrotatedCredentialAndWriteAccess(Rule):
    rule_id = "ACC-006"
    title = "Bot has write access to production and a credential that is not rotating"
    category = "access"
    severity = Severity.CRITICAL
    requires = frozenset({Capability.ACCOUNTS})
    defaults = {"stale_days": 180}

    def evaluate(self) -> Iterator[Candidate]:
        """
        The cross-domain finding, and the argument for keeping access and
        credential lifecycle in one system rather than two.

        Each half is tolerable on its own. A bot with production write access is
        normal. A credential that has not rotated in six months is a
        housekeeping item. Together they are a durable, unmonitored path into
        production that no single team is looking at, because the access belongs
        to one team's register and the credential to another's.
        """
        from access.models import AccessGrant, ELEVATED_LEVELS, NON_HUMAN_PRINCIPALS

        stale = timezone.now() - timedelta(days=self.parameter("stale_days"))
        grants = AccessGrant.objects.filter(
            revoked_at__isnull=True,
            absent_since__isnull=True,
            resource__production=True,
            access_level__in=[level.value for level in ELEVATED_LEVELS],
            principal__principal_type__in=[value for value in NON_HUMAN_PRINCIPALS],
            principal__managed_account__isnull=False,
        ).select_related("principal", "resource", "principal__managed_account")

        for grant in grants:
            account = grant.principal.managed_account
            unrotated = account.last_rotation_at is None or account.last_rotation_at < stale
            if not (unrotated or account.auto_rotation_enabled is False):
                continue
            yield Candidate(
                account=account,
                evidence={
                    "principal": grant.principal.identifier,
                    "resource": grant.resource.identifier,
                    "access_level": grant.access_level,
                    "credential": account.username,
                    "credential_age_days": account.credential_age_days,
                    "auto_rotation_enabled": account.auto_rotation_enabled,
                    "reading": (
                        "A durable credential with production write access. Neither half looks "
                        "urgent in its own register."
                    ),
                },
                subject_key=f"{grant.principal.identifier}:{grant.resource.identifier}",
            )

    def describe(self, candidate: Candidate) -> str:
        return (
            f"{candidate.evidence['principal']} writes to {candidate.evidence['resource']} "
            f"with a credential {candidate.evidence['credential_age_days'] or 'never rotated'} days old"
        )


@register
class DormantAccess(Rule):
    rule_id = "ACC-007"
    title = "Access granted and never used"
    category = "access"
    severity = Severity.MEDIUM
    requires = frozenset({Capability.ACCOUNTS})
    defaults = {"dormant_days": 90}

    def evaluate(self) -> Iterator[Candidate]:
        from access.reconcile import dormant_grants

        anchor = _access_anchor()
        grouped: dict[int, list] = {}
        for grant in dormant_grants(self.parameter("dormant_days")):
            grouped.setdefault(grant.principal_id, []).append(grant)

        for rows in grouped.values():
            principal = rows[0].principal
            account = principal.managed_account or anchor
            if account is None:
                continue
            yield Candidate(
                account=account,
                evidence={
                    "principal": principal.identifier,
                    "dormant_grants": len(rows),
                    "resources": sorted({row.resource.identifier for row in rows})[:8],
                    "recommended_action": "Remove at the next review unless the owner argues otherwise",
                },
                subject_key=principal.identifier,
            )


@register
class ApprovalChainBroken(Rule):
    rule_id = "ACC-008"
    title = "An approval record has been altered after the fact"
    category = "access"
    severity = Severity.CRITICAL
    requires = frozenset({Capability.ACCOUNTS})

    def evaluate(self) -> Iterator[Candidate]:
        """
        Each approval is hashed over its own content and the previous record's
        hash. A decision edited afterwards breaks every link after it. If this
        rule ever fires, the approval evidence for that request cannot be relied
        on and the finding is a security incident, not a data quality issue.
        """
        from access.models import AccessRequest
        from access.workflow import verify_chain

        anchor = _access_anchor()
        if anchor is None:
            return
        for request in AccessRequest.objects.exclude(approvals__isnull=True).distinct():
            intact, message = verify_chain(request)
            if intact:
                continue
            yield Candidate(
                account=request.principal.managed_account or anchor,
                evidence={
                    "request": request.reference,
                    "detail": message,
                    "principal": request.principal.identifier,
                    "resource": request.resource.identifier,
                    "action": "Treat the approval evidence for this request as unreliable",
                },
                subject_key=request.reference,
            )
