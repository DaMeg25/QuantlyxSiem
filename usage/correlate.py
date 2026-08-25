"""
Join what the vault handed out to what the targets saw.

The interesting output is not the matches. It is the two residues:

  * An authentication on a target with no vault retrieval behind it. Someone
    logged in with a managed privileged credential that they did not get from
    the vault on that occasion, which means a working copy exists outside it --
    in a script, a password manager, a runbook, someone's notes. This is the
    single highest-value thing this system can tell you, and no vault can tell
    you it alone, because the vault genuinely did not see the event.

  * A retrieval with no authentication behind it. The credential was pulled and
    apparently not used. Usually benign (a check that failed, an aborted change),
    occasionally not.

Correlation is inference, not proof. Clock skew, batched log delivery, and
shared service accounts all produce false pairings. The window and the
attribution rules below are deliberately conservative, and every observation
keeps the lag that produced its match so a reviewer can judge it.
"""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import timedelta
from typing import Iterable

from django.db.models import Q
from django.utils import timezone

from inventory.models import (
    AssetType,
    CredentialAssetLink,
    LifecycleEvent,
    ManagedAccount,
    TargetAsset,
    UsageObservation,
)

log = logging.getLogger(__name__)

#: How long after a retrieval a login may still plausibly be attributed to it.
#: Longer than the typical session start, short enough that two retrievals of the
#: same credential in a day do not both claim the same login.
DEFAULT_WINDOW = timedelta(hours=4)

#: A login slightly *before* its retrieval is normal: clock skew and the ordering
#: of a session-start record against a checkout record are not guaranteed.
BACKWARD_TOLERANCE = timedelta(minutes=5)


def dedupe_key(*parts: object) -> str:
    return hashlib.sha256("|".join(str(part) for part in parts).encode()).hexdigest()[:48]


def normalize_account_name(raw: str) -> str:
    """
    Strip the decoration targets add, so DOMAIN\\svc_batch, svc_batch@corp.local,
    and svc_batch all resolve to the same managed account.
    """
    name = (raw or "").strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name.lower()


def classify_asset(identifier: str, hint: str = "") -> str:
    subject = f"{identifier} {hint}".lower()
    if re.search(r"(rtr|switch|sw\d|fw|firewall|asa|nexus|apic|ltm|netscaler|wlc|-gw)", subject):
        return AssetType.NETWORK_DEVICE
    if re.search(r"(oradb|pgsql|mssql|mysql|db\d|database)", subject):
        return AssetType.DATABASE
    if re.search(r"(esx|vcenter|hyperv|hypervisor)", subject):
        return AssetType.HYPERVISOR
    if re.search(r"(^dc\d|-dc\d|domain controller|\bldap\b)", subject):
        return AssetType.DIRECTORY
    if re.search(r"(aws|azure|gcp|account:)", subject):
        return AssetType.CLOUD_ACCOUNT
    if re.search(r"(app|service|gateway|api)", subject):
        return AssetType.APPLICATION
    if re.search(r"(srv|host|node|vm-|jump)", subject):
        return AssetType.SERVER
    return AssetType.UNKNOWN


def resolve_asset(identifier: str, *, display_name: str = "", hint: str = "", address: str = "") -> TargetAsset:
    key = (identifier or "unknown").strip().lower()
    asset, created = TargetAsset.objects.get_or_create(
        identifier=key,
        defaults={
            "display_name": display_name or identifier,
            "asset_type": classify_asset(key, hint),
            "address": address,
        },
    )
    if not created:
        changed = []
        if address and not asset.address:
            asset.address = address
            changed.append("address")
        asset.last_seen_at = timezone.now()
        changed.append("last_seen_at")
        asset.save(update_fields=changed)
    return asset


def resolve_account(observed_name: str, asset: TargetAsset) -> ManagedAccount | None:
    """
    Match a target-reported account name to a managed account.

    Preference order matters. An account mapped to this exact asset wins over a
    same-named account elsewhere, because domain administrator names repeat
    across the estate and attributing a login to the wrong vault entry is worse
    than leaving it unattributed.
    """
    name = normalize_account_name(observed_name)
    if not name:
        return None

    scoped = (
        ManagedAccount.objects.live()
        .filter(username__iexact=name)
        .filter(Q(target_address__iexact=asset.identifier) | Q(target_address__iexact=asset.address))
        .first()
    )
    if scoped:
        return scoped

    candidates = list(ManagedAccount.objects.live().filter(username__iexact=name)[:5])
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        log.debug(
            "Account name '%s' is ambiguous across %s vault entries; left unattributed",
            name,
            len(candidates),
        )
    return None


def record_observations(observations: Iterable[dict], source=None) -> int:
    """
    Persist raw usage records. Each dict needs at least:
        observed_account_name, asset_identifier, occurred_at, mechanism
    """
    created = 0
    for row in observations:
        asset = resolve_asset(
            row["asset_identifier"],
            display_name=row.get("asset_display_name", ""),
            hint=row.get("asset_hint", ""),
            address=row.get("asset_address", ""),
        )
        account = resolve_account(row["observed_account_name"], asset)
        key = row.get("dedupe_key") or dedupe_key(
            row["observed_account_name"], asset.identifier, row["occurred_at"], row.get("session_reference", "")
        )
        _, made = UsageObservation.objects.get_or_create(
            dedupe_key=key,
            defaults={
                "account": account,
                "observed_account_name": row["observed_account_name"],
                "asset": asset,
                "source": source,
                "occurred_at": row["occurred_at"],
                "ended_at": row.get("ended_at"),
                "mechanism": row["mechanism"],
                "correlation": (
                    UsageObservation.Correlation.BROKERED
                    if row["mechanism"] in (
                        UsageObservation.Mechanism.BROKERED_SESSION,
                        UsageObservation.Mechanism.APPLICATION_FETCH,
                    )
                    else UsageObservation.Correlation.UNMATCHED_ACCOUNT
                    if account is None
                    else UsageObservation.Correlation.PENDING
                ),
                "actor": row.get("actor", ""),
                "source_address": row.get("source_address", ""),
                "outcome": row.get("outcome", "success"),
                "session_reference": row.get("session_reference", ""),
                "command_count": row.get("command_count"),
                "privilege_level": row.get("privilege_level", ""),
                "detail": row.get("detail", {}),
            },
        )
        created += int(made)
    if source:
        source.last_ingest_at = timezone.now()
        source.records_ingested = (source.records_ingested or 0) + created
        source.save(update_fields=["last_ingest_at", "records_ingested"])
    return created


def correlate(window: timedelta = DEFAULT_WINDOW, limit: int = 20000) -> dict[str, int]:
    """
    Attribute pending target-side authentications to vault retrievals.

    Each retrieval may account for at most one login, so a burst of logins from
    a single checkout leaves the rest unexplained rather than all of them
    inheriting the same justification.
    """
    pending = (
        UsageObservation.objects.filter(correlation=UsageObservation.Correlation.PENDING)
        .select_related("account", "asset")
        .order_by("occurred_at")[:limit]
    )

    matched = unexplained = 0
    claimed: set[int] = set(
        UsageObservation.objects.filter(correlated_event__isnull=False).values_list(
            "correlated_event_id", flat=True
        )
    )

    for observation in pending:
        account = observation.account
        if account is None:
            observation.correlation = UsageObservation.Correlation.UNMATCHED_ACCOUNT
            observation.save(update_fields=["correlation"])
            continue

        candidates = LifecycleEvent.objects.filter(
            account=account,
            kind=LifecycleEvent.Kind.CHECKED_OUT,
            occurred_at__gte=observation.occurred_at - window,
            occurred_at__lte=observation.occurred_at + BACKWARD_TOLERANCE,
        ).order_by("-occurred_at")

        chosen = None
        for candidate in candidates:
            if candidate.pk in claimed:
                continue
            # If both sides name a person, they have to be the same person.
            if observation.actor and candidate.actor and (
                normalize_account_name(observation.actor) != normalize_account_name(candidate.actor)
            ):
                continue
            chosen = candidate
            break

        if chosen:
            claimed.add(chosen.pk)
            observation.correlated_event = chosen
            observation.correlation = UsageObservation.Correlation.MATCHED
            observation.correlation_lag_seconds = int(
                (observation.occurred_at - chosen.occurred_at).total_seconds()
            )
            matched += 1
        else:
            observation.correlation = UsageObservation.Correlation.UNEXPLAINED
            unexplained += 1

        observation.save(
            update_fields=["correlated_event", "correlation", "correlation_lag_seconds"]
        )

    links = rebuild_links()
    return {"matched": matched, "unexplained": unexplained, "asset_links": links}


def rebuild_links() -> int:
    """Refresh the rolled-up credential-to-asset reach table."""
    from django.db.models import Count, Max, Min

    rows = (
        UsageObservation.objects.filter(account__isnull=False)
        .values("account_id", "asset_id")
        .annotate(
            first=Min("occurred_at"),
            last=Max("occurred_at"),
            total=Count("id"),
        )
    )
    written = 0
    for row in rows:
        account = ManagedAccount.objects.filter(pk=row["account_id"]).only(
            "id", "target_address"
        ).first()
        asset = TargetAsset.objects.filter(pk=row["asset_id"]).only("id", "identifier", "address").first()
        if not account or not asset:
            continue
        mechanisms = sorted(
            UsageObservation.objects.filter(
                account_id=row["account_id"], asset_id=row["asset_id"]
            ).values_list("mechanism", flat=True).distinct()
        )
        unexplained = UsageObservation.objects.filter(
            account_id=row["account_id"],
            asset_id=row["asset_id"],
            correlation=UsageObservation.Correlation.UNEXPLAINED,
        ).count()
        mapped = (account.target_address or "").strip().lower()
        outside = bool(mapped) and mapped not in (asset.identifier, (asset.address or "").lower())

        CredentialAssetLink.objects.update_or_create(
            account_id=row["account_id"],
            asset_id=row["asset_id"],
            defaults={
                "first_seen_at": row["first"],
                "last_seen_at": row["last"],
                "observation_count": row["total"],
                "unexplained_count": unexplained,
                "mechanisms": mechanisms,
                "outside_mapped_scope": outside,
            },
        )
        written += 1
    return written
