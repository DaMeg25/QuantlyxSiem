"""
Compare what the platforms report against what was approved.

This is where the module earns its place. The approval workflow on its own is a
form with a state machine; plenty of organisations have one and still cannot
answer the two questions an examiner actually asks:

  * Does anyone hold access that was never approved?
  * Did the access that expired on paper actually go away?

Both are reconciliation questions, and both are answered by enumerating the
platform and diffing against the grant table. The same shape as the credential
work elsewhere in this system: the vault says what it handed out, the target
says what happened, and the disagreement is the finding.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Iterable

from django.db import transaction
from django.utils import timezone

from access.models import (
    AccessGrant,
    AccessRequest,
    ELEVATED_LEVELS,
    Principal,
    PrincipalType,
    Resource,
)
from resources.base import NormalizedAccess, NormalizedResource

log = logging.getLogger(__name__)


def resolve_principal(record: NormalizedAccess) -> Principal:
    principal, created = Principal.objects.get_or_create(
        identifier=record.principal_identifier,
        defaults={
            "display_name": record.display_name,
            "email": record.email,
            "principal_type": record.principal_type or PrincipalType.UNKNOWN,
        },
    )
    changed = []
    if record.machine_identity and principal.principal_type != PrincipalType.BOT:
        principal.principal_type = PrincipalType.BOT
        changed.append("principal_type")
    if record.display_name and not principal.display_name:
        principal.display_name = record.display_name
        changed.append("display_name")
    if record.email and not principal.email:
        principal.email = record.email
        changed.append("email")
    principal.last_seen_at = timezone.now()
    changed.append("last_seen_at")
    if changed:
        principal.save(update_fields=changed)
    return principal


@transaction.atomic
def reconcile_resources(platform: str, resources: Iterable[NormalizedResource]) -> dict[str, int]:
    seen, created = set(), 0
    for record in resources:
        if not record.identifier:
            continue
        seen.add(record.identifier)
        resource, made = Resource.objects.get_or_create(
            platform=platform,
            identifier=record.identifier,
            defaults={
                "display_name": record.display_name,
                "url": record.url,
                "production": record.production,
                "archived": record.archived,
                "owner_team": record.owner_team,
            },
        )
        created += int(made)
        resource.display_name = record.display_name or resource.display_name
        resource.url = record.url or resource.url
        resource.archived = record.archived
        # Production is derived from platform metadata, so let it change, but
        # never silently downgrade a resource an operator marked critical.
        if record.production:
            resource.production = True
        resource.detail = record.detail
        resource.save(update_fields=["display_name", "url", "archived", "production", "detail"])
    return {"resources_seen": len(seen), "resources_created": created}


@transaction.atomic
def reconcile_access(resource: Resource, records: Iterable[NormalizedAccess]) -> dict[str, int]:
    """
    Bring the grant table in line with what the platform reports.

    Three outcomes per grant, and the second is the one worth reading twice:

      * Present and traceable to an approved request. Governed access.
      * Present with nothing behind it. The access is real; the authority for it
        is not recorded anywhere. Rule ACC-001.
      * Absent, but a grant row says it should be there. Either it was removed
        outside this process, or an expiry finally took effect. Recorded as
        absent rather than deleted, so the history survives.
    """
    now = timezone.now()
    seen_keys: set[tuple[int, str]] = set()
    discovered = confirmed = 0

    for record in records:
        principal = resolve_principal(record)
        key = (principal.pk, record.access_level)
        seen_keys.add(key)

        grant = AccessGrant.objects.filter(
            principal=principal, resource=resource, access_level=record.access_level
        ).first()

        if grant is None:
            request = _matching_request(principal, resource, record.access_level)
            grant = AccessGrant.objects.create(
                principal=principal,
                resource=resource,
                access_level=record.access_level,
                origin=AccessGrant.Origin.APPROVED if request else AccessGrant.Origin.DISCOVERED,
                request=request,
                granted_at=record.granted_at or now,
                expires_at=request.expires_at if request else record.expires_at,
                last_confirmed_at=now,
                last_used_at=record.last_used_at,
                detail=record.detail,
            )
            discovered += int(request is None)
            if request is None:
                log.info(
                    "Access with no approved request behind it: %s holds %s on %s",
                    principal, record.access_level, resource,
                )
        else:
            grant.last_confirmed_at = now
            grant.absent_since = None
            if record.last_used_at:
                grant.last_used_at = record.last_used_at
            if grant.request is None:
                # A request may have been approved after the access appeared.
                matched = _matching_request(principal, resource, record.access_level)
                if matched:
                    grant.request = matched
                    grant.origin = AccessGrant.Origin.APPROVED
                    grant.expires_at = matched.expires_at
            grant.detail = record.detail or grant.detail
            grant.save()
            confirmed += 1

    # Anything the platform no longer reports.
    removed = 0
    for grant in AccessGrant.objects.filter(resource=resource, absent_since__isnull=True):
        if (grant.principal_id, grant.access_level) in seen_keys:
            continue
        grant.absent_since = now
        grant.save(update_fields=["absent_since"])
        removed += 1

    resource.last_reconciled_at = now
    resource.save(update_fields=["last_reconciled_at"])
    return {"confirmed": confirmed, "discovered_unapproved": discovered, "no_longer_present": removed}


def _matching_request(principal: Principal, resource: Resource, access_level: str) -> AccessRequest | None:
    return (
        AccessRequest.objects.filter(
            principal=principal,
            resource=resource,
            access_level=access_level,
            state__in=[AccessRequest.State.APPROVED, AccessRequest.State.PROVISIONED],
        )
        .order_by("-decided_at")
        .first()
    )


def link_bot_credentials() -> int:
    """
    Join non-human principals to the vaulted credential they authenticate with.

    This is what makes "bot with write access to a production repository whose
    credential has never been rotated" one query instead of a spreadsheet
    exercise across two teams. Matching is on stated identifiers only -- a
    guessed link would put a rotation finding on the wrong bot.
    """
    from inventory.models import ManagedAccount

    linked = 0
    for principal in Principal.objects.filter(
        principal_type__in=[PrincipalType.BOT, PrincipalType.SERVICE], managed_account__isnull=True
    ):
        name = principal.identifier.split(":")[-1].replace("[bot]", "").strip().lower()
        if not name or len(name) < 4:
            continue
        matches = list(ManagedAccount.objects.live().filter(username__iexact=name)[:2])
        if len(matches) == 1:
            principal.managed_account = matches[0]
            principal.save(update_fields=["managed_account"])
            linked += 1
    return linked


def stale_expiries() -> list[AccessGrant]:
    """Grants past their expiry that the platform still reports as present."""
    return list(
        AccessGrant.objects.filter(
            expires_at__lt=timezone.now(),
            revoked_at__isnull=True,
            absent_since__isnull=True,
        ).select_related("principal", "resource", "request")
    )


def elevated_standing_access(production_only: bool = True):
    queryset = AccessGrant.objects.filter(
        expires_at__isnull=True,
        revoked_at__isnull=True,
        absent_since__isnull=True,
        access_level__in=[level.value for level in ELEVATED_LEVELS],
    ).select_related("principal", "resource")
    if production_only:
        queryset = queryset.filter(resource__production=True)
    return queryset


def dormant_grants(days: int = 90):
    cutoff = timezone.now() - timedelta(days=days)
    return AccessGrant.objects.filter(
        revoked_at__isnull=True,
        absent_since__isnull=True,
        last_used_at__lt=cutoff,
    ).select_related("principal", "resource")
