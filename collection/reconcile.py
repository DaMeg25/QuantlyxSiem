"""
Turn a full inventory pull into stored state plus a stream of lifecycle events.

The interesting work is the diff. A Privileged Access Management platform tells
you what is true now; it rarely tells you what changed. Comparing each pull
against the stored row is what produces "this bot account's automatic rotation
was switched off on Tuesday", which is the finding an auditor actually wants.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import asdict
from datetime import datetime, timedelta
from typing import Iterable

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from connectors.base import NormalizedAccount, NormalizedActivity
from inventory.models import (
    AccountSnapshot,
    AccountStatus,
    CollectionRun,
    LifecycleEvent,
    ManagedAccount,
    PamSystem,
)

log = logging.getLogger(__name__)

#: Fields compared between pulls to derive lifecycle events.
TRACKED_FIELDS = (
    "status",
    "owner_identity",
    "owner_team",
    "auto_rotation_enabled",
    "last_rotation_at",
    "verification_ok",
    "rotation_interval_days",
    "exclusive_checkout",
)

#: Vendor audit verbs mapped onto normalized event kinds.
ACTION_MAP = {
    "cpm change password": LifecycleEvent.Kind.ROTATED,
    "change password": LifecycleEvent.Kind.ROTATED,
    "password changed": LifecycleEvent.Kind.ROTATED,
    "cpm verify password": LifecycleEvent.Kind.VERIFICATION_FAILED,
    "retrieve password": LifecycleEvent.Kind.CHECKED_OUT,
    "checkout": LifecycleEvent.Kind.CHECKED_OUT,
    "check out": LifecycleEvent.Kind.CHECKED_OUT,
    "checkin": LifecycleEvent.Kind.CHECKED_IN,
    "check in": LifecycleEvent.Kind.CHECKED_IN,
}


def dedupe_key(*parts: object) -> str:
    raw = "|".join(str(part) for part in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:48]


@transaction.atomic
def reconcile_accounts(
    system: PamSystem,
    run: CollectionRun,
    accounts: Iterable[NormalizedAccount],
    *,
    write_snapshots: bool = True,
) -> None:
    seen_ids: set[str] = set()
    created = updated = 0

    for incoming in accounts:
        seen_ids.add(incoming.external_id)
        existing = ManagedAccount.objects.filter(
            system=system, external_id=incoming.external_id
        ).first()

        events = []
        if existing is None:
            account = _create_account(system, incoming)
            created += 1
            _record_event(
                account,
                LifecycleEvent.Kind.ONBOARDED,
                occurred_at=account.onboarded_at or timezone.now(),
                detail={"container": account.container, "kind": account.kind},
            )
        else:
            account = existing
            events = _apply_update(account, incoming)
            updated += 1
            for kind, occurred_at, detail in events:
                _record_event(account, kind, occurred_at=occurred_at, detail=detail)

        if write_snapshots and _should_snapshot(account, changed=bool(existing is None or events)):
            AccountSnapshot.objects.create(
                account=account,
                run=run,
                status=account.status,
                last_rotation_at=account.last_rotation_at,
                auto_rotation_enabled=account.auto_rotation_enabled,
                verification_ok=account.verification_ok,
                owner_identity=account.owner_identity,
                credential_age_days=account.credential_age_days,
            )

    retired = _retire_missing(system, seen_ids)

    run.accounts_seen = len(seen_ids)
    run.accounts_created = created
    run.accounts_updated = updated
    run.accounts_retired = retired
    run.save(update_fields=["accounts_seen", "accounts_created", "accounts_updated", "accounts_retired"])


def _should_snapshot(account: ManagedAccount, *, changed: bool) -> bool:
    """
    Write a snapshot when something changed, or when the last one is old enough
    to keep the historical series honest.

    A row per account per collection run is the obvious implementation and it
    does not survive contact with a real estate: ten thousand accounts collected
    every half hour is half a million rows a day, almost all of them identical
    to the row before. Change-driven writes plus one heartbeat a day give the
    same posture history for a fraction of the volume.
    """
    if changed:
        return True
    interval = timedelta(
        hours=float(getattr(settings, "SNAPSHOT_MIN_INTERVAL_HOURS", 24))
    )
    latest = (
        AccountSnapshot.objects.filter(account=account)
        .order_by("-captured_at")
        .values_list("captured_at", flat=True)
        .first()
    )
    return latest is None or timezone.now() - latest >= interval


def _create_account(system: PamSystem, incoming: NormalizedAccount) -> ManagedAccount:
    payload = asdict(incoming)
    raw = payload.pop("raw", {})
    payload.pop("external_id")
    return ManagedAccount.objects.create(
        system=system,
        external_id=incoming.external_id,
        raw=raw,
        first_seen_at=timezone.now(),
        last_seen_at=timezone.now(),
        **payload,
    )


def _apply_update(account: ManagedAccount, incoming: NormalizedAccount):
    """Mutate the stored account and return the lifecycle transitions observed."""
    events: list[tuple[str, datetime, dict]] = []
    now = timezone.now()

    before = {field: getattr(account, field) for field in TRACKED_FIELDS}

    payload = asdict(incoming)
    raw = payload.pop("raw", {})
    payload.pop("external_id")
    for field, value in payload.items():
        setattr(account, field, value)
    account.raw = raw
    account.last_seen_at = now

    # Rotation
    if incoming.last_rotation_at and before["last_rotation_at"] != incoming.last_rotation_at:
        events.append(
            (
                LifecycleEvent.Kind.ROTATED,
                incoming.last_rotation_at,
                {
                    "previous_rotation": before["last_rotation_at"].isoformat()
                    if before["last_rotation_at"]
                    else None,
                    "interval_days": incoming.rotation_interval_days,
                },
            )
        )
        account.consecutive_rotation_failures = 0

    if incoming.last_rotation_failed:
        account.consecutive_rotation_failures = (account.consecutive_rotation_failures or 0) + 1
        events.append(
            (
                LifecycleEvent.Kind.ROTATION_FAILED,
                now,
                {
                    "reason": incoming.rotation_failure_reason,
                    "consecutive": account.consecutive_rotation_failures,
                },
            )
        )
    elif not incoming.last_rotation_failed and before["last_rotation_at"] == incoming.last_rotation_at:
        pass

    # Automatic rotation toggled
    if before["auto_rotation_enabled"] is not None and (
        before["auto_rotation_enabled"] != incoming.auto_rotation_enabled
    ):
        kind = (
            LifecycleEvent.Kind.AUTO_ROTATION_ENABLED
            if incoming.auto_rotation_enabled
            else LifecycleEvent.Kind.AUTO_ROTATION_DISABLED
        )
        events.append((kind, now, {"previous": before["auto_rotation_enabled"]}))

    # Ownership
    if before["owner_identity"] != incoming.owner_identity:
        events.append(
            (
                LifecycleEvent.Kind.OWNERSHIP_CHANGED,
                now,
                {"from": before["owner_identity"], "to": incoming.owner_identity},
            )
        )

    # Status
    if before["status"] != incoming.status:
        events.append(
            (
                LifecycleEvent.Kind.STATUS_CHANGED,
                now,
                {"from": before["status"], "to": incoming.status},
            )
        )

    # Verification
    if incoming.verification_ok is False and before["verification_ok"] is not False:
        events.append(
            (
                LifecycleEvent.Kind.VERIFICATION_FAILED,
                incoming.last_verification_at or now,
                {"detail": "Vault credential no longer matches the target system"},
            )
        )

    account.risk_score = compute_risk_score(account)
    account.save()
    return events


def _retire_missing(system: PamSystem, seen_ids: set[str]) -> int:
    """
    Accounts absent from a complete pull have been removed from the vault.

    Guard rail: if a pull returns suspiciously few accounts, do not mass-retire.
    A vendor outage that returns an empty page would otherwise generate a
    catastrophic false "everything was deleted" event storm.
    """
    live = ManagedAccount.objects.filter(system=system).exclude(status=AccountStatus.DELETED)
    live_count = live.count()
    if live_count and len(seen_ids) < live_count * 0.5:
        log.error(
            "Refusing to retire accounts for %s: pull returned %s of %s known accounts",
            system.name,
            len(seen_ids),
            live_count,
        )
        return 0

    missing = live.exclude(external_id__in=seen_ids)
    retired = 0
    for account in missing:
        account.status = AccountStatus.DELETED
        account.retired_at = timezone.now()
        account.save(update_fields=["status", "retired_at"])
        _record_event(
            account,
            LifecycleEvent.Kind.RETIRED,
            occurred_at=account.retired_at,
            detail={"last_seen_at": account.last_seen_at.isoformat()},
        )
        retired += 1
    return retired


def _record_event(account: ManagedAccount, kind: str, *, occurred_at, detail: dict, actor: str = "collector", outcome: str = "") -> None:
    key = dedupe_key(account.pk, kind, occurred_at, sorted(detail.items()))
    LifecycleEvent.objects.get_or_create(
        dedupe_key=key,
        defaults={
            "account": account,
            "kind": kind,
            "occurred_at": occurred_at,
            "actor": actor,
            "outcome": outcome,
            "detail": detail,
        },
    )


def ingest_activity(system: PamSystem, activities: Iterable[NormalizedActivity]) -> int:
    """Store vendor audit events against the accounts they belong to."""
    index = {
        account.external_id: account
        for account in ManagedAccount.objects.filter(system=system).only("id", "external_id")
    }
    count = 0
    for activity in activities:
        account = index.get(activity.account_external_id)
        if account is None:
            continue
        kind = ACTION_MAP.get(activity.action.strip().lower(), LifecycleEvent.Kind.VENDOR_AUDIT)
        key = dedupe_key(system.pk, activity.external_id, activity.action)
        _, made = LifecycleEvent.objects.get_or_create(
            dedupe_key=key,
            defaults={
                "account": account,
                "kind": kind,
                "occurred_at": activity.occurred_at,
                "actor": activity.actor,
                "source_address": activity.source_address,
                "outcome": activity.outcome,
                "ticket_reference": activity.ticket_reference,
                "detail": {"action": activity.action, "reason": activity.reason},
            },
        )
        count += int(made)
    return count


def compute_risk_score(account: ManagedAccount) -> int:
    """
    A 0-100 blended score used only for sorting the dashboard. It is not a
    control; every real decision comes from a named rule with named evidence.
    """
    score = 0
    pressure = account.rotation_pressure
    score += min(40, int(pressure * 25))
    if account.auto_rotation_enabled is False:
        score += 20
    if account.is_non_human and not account.owner_identity:
        score += 15
    if account.consecutive_rotation_failures:
        score += min(15, account.consecutive_rotation_failures * 5)
    if account.verification_ok is False:
        score += 10
    if account.exclusive_checkout is False and account.kind == "human":
        score += 5
    dormant = account.dormant_days
    if dormant is not None and dormant > 90 and account.status == AccountStatus.ACTIVE:
        score += 10
    return max(0, min(100, score))
