"""
The approval workflow.

Every rule enforced here exists because the failure it prevents is one that
survives a control test. Segregation of duties is checked at the moment of
decision rather than reported afterwards, because an approval that should not
have happened is not fixed by noticing it later. Durations are capped at
submission, because "we will review it at the next recertification" is how
standing access is created. And the approval chain is hashed, because an audit
record that can be quietly edited is not evidence.

Provisioning is not performed here. `hand_off` records that the change was
passed to whatever actually performs it, and the reconciliation pass in
`access/reconcile.py` later checks whether it happened.
"""

from __future__ import annotations

import logging
import secrets
from datetime import timedelta
from typing import Iterable

from django.db import transaction
from django.utils import timezone

from .models import (
    AccessGrant,
    AccessLevel,
    AccessRequest,
    ApprovalPolicy,
    ApprovalStep,
    Approver,
    Criticality,
    ELEVATED_LEVELS,
    Principal,
    Resource,
    default_grant_days,
    max_grant_days,
)

log = logging.getLogger(__name__)

CRITICALITY_ORDER = {
    Criticality.LOW: 0,
    Criticality.MODERATE: 1,
    Criticality.HIGH: 2,
    Criticality.CRITICAL: 3,
}


class WorkflowError(RuntimeError):
    """A request that policy will not allow. The message is shown to the requester."""


class SegregationOfDutiesError(WorkflowError):
    pass


def new_reference() -> str:
    return f"ACR{timezone.now():%Y%m}{secrets.token_hex(3).upper()}"


# --------------------------------------------------------------------------
# Policy resolution
# --------------------------------------------------------------------------


def resolve_policy(resource: Resource, principal: Principal, access_level: str) -> ApprovalPolicy | None:
    """
    Most specific policy wins: one naming the resource beats one naming the
    platform, which beats the catch-all. Ties break toward the stricter policy,
    so a configuration mistake fails closed.
    """
    candidates = []
    for policy in ApprovalPolicy.objects.filter(enabled=True):
        if policy.resource_id and policy.resource_id != resource.pk:
            continue
        if policy.platform and policy.platform != resource.platform:
            continue
        if policy.applies_to_production_only and not resource.production:
            continue
        if policy.minimum_criticality and CRITICALITY_ORDER.get(
            resource.criticality, 0
        ) < CRITICALITY_ORDER.get(policy.minimum_criticality, 0):
            continue
        if policy.access_levels and access_level not in policy.access_levels:
            continue
        if policy.principal_types and principal.principal_type not in policy.principal_types:
            continue
        candidates.append(policy)

    if not candidates:
        return None
    candidates.sort(
        key=lambda policy: (policy.specificity, policy.approvals_required, -policy.maximum_duration_days),
        reverse=True,
    )
    return candidates[0]


# --------------------------------------------------------------------------
# Submission
# --------------------------------------------------------------------------


@transaction.atomic
def submit(
    *,
    principal: Principal,
    resource: Resource,
    access_level: str,
    requested_by: str,
    justification: str = "",
    ticket_reference: str = "",
    requested_days: int | None = None,
) -> AccessRequest:
    if access_level not in {choice.value for choice in AccessLevel}:
        raise WorkflowError(f"Unknown access level '{access_level}'")
    if resource.archived:
        raise WorkflowError(f"{resource} is archived; access to it cannot be granted")
    if not principal.active:
        raise WorkflowError(f"{principal} is not an active identity")

    policy = resolve_policy(resource, principal, access_level)

    if policy and policy.require_justification and not justification.strip():
        raise WorkflowError(
            "This resource requires a written justification. "
            "The reason is what a reviewer reads at recertification, so 'access needed' is not one."
        )
    if policy and policy.require_ticket_reference and not ticket_reference.strip():
        raise WorkflowError("This resource requires a change or incident reference")

    # A non-human principal must name a human who answers for it. Without this,
    # a bot's access has no one to attest to it and survives every review.
    if principal.is_non_human and policy and policy.require_owner_for_bots:
        if not principal.responsible_owner:
            raise WorkflowError(
                f"{principal} is a non-human identity with no responsible owner recorded. "
                "Name the human accountable for it before requesting access."
            )

    ceiling = min(policy.maximum_duration_days if policy else max_grant_days(), max_grant_days())
    days = requested_days or (policy.maximum_duration_days if policy else default_grant_days())
    standing = requested_days == 0
    if standing:
        if not (policy and policy.standing_access_allowed):
            raise WorkflowError(
                "Standing access is not permitted here. Request a bounded period; "
                "if the need is permanent, that is a conversation for the resource owner, "
                "not a default."
            )
        days = None
    elif days > ceiling:
        raise WorkflowError(
            f"{days} days exceeds the {ceiling} day ceiling for this resource. "
            "Request less, or have the resource owner raise the policy limit explicitly."
        )

    request = AccessRequest.objects.create(
        reference=new_reference(),
        principal=principal,
        resource=resource,
        access_level=access_level,
        requested_by=requested_by,
        justification=justification.strip(),
        ticket_reference=ticket_reference.strip(),
        requested_days=days,
        policy=policy,
        approvals_required=policy.approvals_required if policy else 1,
        state=AccessRequest.State.PENDING,
    )
    log.info(
        "Access request %s raised: %s wants %s on %s",
        request.reference, principal, access_level, resource,
    )
    return request


# --------------------------------------------------------------------------
# Decisions
# --------------------------------------------------------------------------


def check_segregation(request: AccessRequest, approver_identity: str, approver: Approver | None) -> None:
    """
    Four checks, in the order they are most often violated.

    These are enforced, not reported. A control that raises a finding after a
    self-approval has already granted production write access has not prevented
    anything.
    """
    identity = approver_identity.strip().lower()

    if identity == (request.requested_by or "").strip().lower():
        raise SegregationOfDutiesError(
            "The requester cannot approve their own request."
        )
    if identity == (request.principal.identifier or "").strip().lower() or identity == (
        request.principal.email or ""
    ).strip().lower():
        raise SegregationOfDutiesError(
            "A person cannot approve access for themselves."
        )
    if request.principal.is_non_human and identity == (
        request.principal.responsible_owner or ""
    ).strip().lower() and (request.principal.responsible_owner or "").strip().lower() == (
        request.requested_by or ""
    ).strip().lower():
        raise SegregationOfDutiesError(
            "The bot's owner raised this request and cannot also be its only approver."
        )
    if request.approvals.filter(approver_identity__iexact=identity).exists():
        raise SegregationOfDutiesError(
            "This approver has already recorded a decision on this request."
        )

    policy = request.policy
    if policy and policy.approver_groups:
        groups = set(approver.groups if approver else [])
        if not groups & set(policy.approver_groups):
            raise SegregationOfDutiesError(
                f"Approval here requires membership of one of {sorted(policy.approver_groups)}."
            )
    if approver and approver.independent and approver.team and approver.team == request.principal.team:
        raise SegregationOfDutiesError(
            "This approver is designated independent and cannot approve for their own team."
        )


@transaction.atomic
def decide(
    request: AccessRequest,
    *,
    approver_identity: str,
    decision: str,
    comment: str = "",
    source_address: str = "",
) -> AccessRequest:
    if request.state != AccessRequest.State.PENDING:
        raise WorkflowError(f"{request.reference} is {request.get_state_display()}, not awaiting a decision")

    approver = Approver.objects.filter(identifier__iexact=approver_identity, active=True).first()
    check_segregation(request, approver_identity, approver)

    previous = request.approvals.order_by("-sequence").first()
    step = ApprovalStep(
        request=request,
        sequence=(previous.sequence + 1) if previous else 1,
        approver_identity=approver_identity,
        approver_groups=list(approver.groups) if approver else [],
        decision=decision,
        comment=comment.strip(),
        source_address=source_address,
        previous_hash=previous.content_hash if previous else "",
    )
    step.save()

    if decision == ApprovalStep.Decision.REJECTED:
        request.state = AccessRequest.State.REJECTED
        request.decided_at = timezone.now()
        request.decision_note = comment.strip()
        request.save(update_fields=["state", "decided_at", "decision_note"])
        return request

    if request.approvals_recorded >= request.approvals_required:
        request.state = AccessRequest.State.APPROVED
        request.decided_at = timezone.now()
        request.save(update_fields=["state", "decided_at"])
    return request


@transaction.atomic
def hand_off(request: AccessRequest, *, system: str, reference: str) -> AccessRequest:
    """
    Record that provisioning was passed to the system that performs it.

    This deliberately does not grant anything. The grant row is created by the
    reconciliation pass once the platform actually reports the access, which is
    what makes "approved but never provisioned" and "provisioned but never
    approved" both visible.
    """
    if request.state != AccessRequest.State.APPROVED:
        raise WorkflowError(f"{request.reference} is not approved")
    request.handoff_system = system
    request.handoff_reference = reference
    request.provisioned_at = timezone.now()
    if request.requested_days:
        request.expires_at = timezone.now() + timedelta(days=request.requested_days)
    request.state = AccessRequest.State.PROVISIONED
    request.save(
        update_fields=["handoff_system", "handoff_reference", "provisioned_at", "expires_at", "state"]
    )
    return request


@transaction.atomic
def revoke(request: AccessRequest, *, reason: str = "") -> AccessRequest:
    request.state = AccessRequest.State.REVOKED
    request.decision_note = reason
    request.save(update_fields=["state", "decision_note"])
    AccessGrant.objects.filter(request=request, revoked_at__isnull=True).update(
        revoked_at=timezone.now()
    )
    return request


def expire_due() -> int:
    """Mark requests past their window. Whether the access actually went away is
    a separate question, answered by reconciliation and rule ACC-002."""
    due = AccessRequest.objects.filter(
        state=AccessRequest.State.PROVISIONED,
        expires_at__lt=timezone.now(),
    )
    count = due.count()
    due.update(state=AccessRequest.State.EXPIRED)
    return count


# --------------------------------------------------------------------------
# Tamper evidence
# --------------------------------------------------------------------------


def verify_chain(request: AccessRequest) -> tuple[bool, str]:
    """
    Recompute every approval hash. Returns (intact, description).

    An approval record that can be edited afterwards is not evidence of
    anything, so this is worth running before an approval is relied on in an
    audit response.
    """
    previous_hash = ""
    for step in request.approvals.order_by("sequence"):
        if step.previous_hash != previous_hash:
            return False, f"Step {step.sequence} does not follow step {step.sequence - 1}"
        expected = step.compute_hash()
        if expected != step.content_hash:
            return False, f"Step {step.sequence} by {step.approver_identity} has been altered"
        previous_hash = step.content_hash
    return True, f"{request.approvals.count()} approval records intact"


def verify_all(requests: Iterable[AccessRequest] | None = None) -> dict[str, list[str]]:
    intact, broken = [], []
    for request in requests or AccessRequest.objects.exclude(approvals__isnull=True).distinct():
        ok, message = verify_chain(request)
        (intact if ok else broken).append(f"{request.reference}: {message}")
    return {"intact": intact, "broken": broken}
