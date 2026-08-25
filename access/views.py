"""
The request and approval screens.

Everything here is a thin layer over `access.workflow`. Views never decide
whether something is allowed; they ask the workflow, and render the refusal when
it says no. That matters because the same rules have to hold for a request
raised through the read interface, a management command, or a future integration
with the service desk.
"""

from __future__ import annotations

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from .forms import AccessRequestForm, DecisionForm, HandoffForm, approver_for, can_decide, identity_for
from .models import AccessGrant, AccessRequest, ApprovalStep, Principal, Resource
from .workflow import (
    SegregationOfDutiesError,
    WorkflowError,
    decide,
    hand_off,
    resolve_policy,
    revoke,
    submit,
    verify_chain,
)


def _source_address(request) -> str:
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    return (forwarded.split(",")[0] if forwarded else request.META.get("REMOTE_ADDR", "")).strip()[:64]


@login_required
def request_create(request):
    """Raise a request. The policy that will apply is shown before submission."""
    if request.method == "POST":
        form = AccessRequestForm(request.POST)
        if form.is_valid():
            try:
                created = submit(
                    principal=form.cleaned_data["principal"],
                    resource=form.cleaned_data["resource"],
                    access_level=form.cleaned_data["access_level"],
                    requested_by=identity_for(request.user),
                    justification=form.cleaned_data.get("justification", ""),
                    ticket_reference=form.cleaned_data.get("ticket_reference", ""),
                    requested_days=form.cleaned_data.get("requested_days"),
                )
            except WorkflowError as exc:
                # The workflow refused something the form let through. Its
                # message is written for the requester, so show it verbatim.
                form.add_error(None, str(exc))
            else:
                messages.success(
                    request,
                    f"{created.reference} raised. It needs {created.approvals_required} "
                    f"approval{'s' if created.approvals_required != 1 else ''} before provisioning.",
                )
                return redirect("access-request-detail", reference=created.reference)
    else:
        form = AccessRequestForm(
            initial={
                "principal": request.GET.get("principal"),
                "resource": request.GET.get("resource"),
                "access_level": request.GET.get("access_level"),
            }
        )

    return render(
        request,
        "access/request_form.html",
        {
            "page": "access",
            "form": form,
            "policies": _policy_preview(),
        },
    )


def _policy_preview() -> list[dict]:
    """
    What each production resource will demand, shown alongside the form.

    Requesters otherwise discover the ceiling by having a request refused, and
    the lesson they take from that is to ask for the maximum every time.
    """
    rows = []
    for resource in Resource.objects.filter(archived=False, production=True).order_by("identifier")[:12]:
        policy = resolve_policy(resource, Principal(principal_type="developer"), "write")
        rows.append(
            {
                "resource": resource,
                "policy": policy,
                "approvals": policy.approvals_required if policy else 1,
                "ceiling": policy.maximum_duration_days if policy else None,
            }
        )
    return rows


@login_required
def request_detail(request, reference: str):
    access_request = get_object_or_404(
        AccessRequest.objects.select_related("principal", "resource", "policy"),
        reference=reference,
    )
    allowed, refusal = can_decide(request.user, access_request)
    intact, chain_message = verify_chain(access_request)

    return render(
        request,
        "access/request_detail.html",
        {
            "page": "access",
            "object": access_request,
            "steps": access_request.approvals.order_by("sequence"),
            "can_decide": allowed,
            "refusal": refusal,
            "decision_form": DecisionForm(),
            "handoff_form": HandoffForm(),
            "chain_intact": intact,
            "chain_message": chain_message,
            "grants": AccessGrant.objects.filter(request=access_request).select_related("resource"),
            "viewer": identity_for(request.user),
            "is_approver": approver_for(request.user) is not None,
        },
    )


@login_required
@require_POST
def request_decide(request, reference: str):
    access_request = get_object_or_404(AccessRequest, reference=reference)
    form = DecisionForm(request.POST)
    if not form.is_valid():
        for error in form.errors.values():
            messages.error(request, "; ".join(error))
        return redirect("access-request-detail", reference=reference)

    try:
        decide(
            access_request,
            approver_identity=identity_for(request.user),
            decision=form.cleaned_data["decision"],
            comment=form.cleaned_data.get("comment", ""),
            source_address=_source_address(request),
        )
    except SegregationOfDutiesError as exc:
        # Refused, and worth saying plainly rather than as a generic error.
        messages.error(request, f"Refused: {exc}")
    except WorkflowError as exc:
        messages.error(request, str(exc))
    else:
        access_request.refresh_from_db()
        if access_request.state == AccessRequest.State.APPROVED:
            messages.success(
                request,
                f"{reference} is approved. It is not provisioned until the handoff is recorded.",
            )
        elif access_request.state == AccessRequest.State.REJECTED:
            messages.success(request, f"{reference} rejected.")
        else:
            messages.success(
                request,
                f"Decision recorded. {access_request.approvals_recorded} of "
                f"{access_request.approvals_required} approvals.",
            )
    return redirect("access-request-detail", reference=reference)


@login_required
@require_POST
def request_handoff(request, reference: str):
    access_request = get_object_or_404(AccessRequest, reference=reference)
    form = HandoffForm(request.POST)
    if not form.is_valid():
        messages.error(request, "A provisioning system and task reference are both needed.")
        return redirect("access-request-detail", reference=reference)
    try:
        hand_off(
            access_request,
            system=form.cleaned_data["handoff_system"],
            reference=form.cleaned_data["handoff_reference"],
        )
    except WorkflowError as exc:
        messages.error(request, str(exc))
    else:
        messages.success(
            request,
            "Handoff recorded. The grant appears once the platform reports the access, "
            "which is also what makes an approval that never got provisioned visible.",
        )
    return redirect("access-request-detail", reference=reference)


@login_required
@require_POST
def request_revoke(request, reference: str):
    access_request = get_object_or_404(AccessRequest, reference=reference)
    revoke(access_request, reason=request.POST.get("reason", "")[:500])
    messages.success(
        request,
        "Revoked here. Removing the access on the platform is a separate action; "
        "reconciliation will report it as expired-but-live until it happens.",
    )
    return redirect("access-request-detail", reference=reference)


@login_required
def approval_queue(request):
    """
    What this user can act on, and what they raised.

    Split deliberately: the two lists are disjoint by construction, because
    nobody may approve what they requested. Seeing them side by side is the
    clearest way to make that rule obvious rather than surprising.
    """
    identity = identity_for(request.user)
    approver = approver_for(request.user)

    pending = list(
        AccessRequest.objects.filter(state=AccessRequest.State.PENDING)
        .select_related("principal", "resource", "policy")
        .order_by("created_at")
    )
    actionable, blocked = [], []
    for item in pending:
        allowed, refusal = can_decide(request.user, item)
        (actionable if allowed else blocked).append({"request": item, "refusal": refusal})

    mine = (
        AccessRequest.objects.filter(
            Q(requested_by__iexact=identity) | Q(principal__email__iexact=identity)
        )
        .select_related("principal", "resource")
        .order_by("-created_at")[:25]
    )
    awaiting_handoff = (
        AccessRequest.objects.filter(state=AccessRequest.State.APPROVED)
        .select_related("principal", "resource")
        .order_by("decided_at")[:25]
    )

    return render(
        request,
        "access/queue.html",
        {
            "page": "access",
            "identity": identity,
            "approver": approver,
            "actionable": actionable,
            "blocked": blocked,
            "mine": mine,
            "awaiting_handoff": awaiting_handoff,
        },
    )
