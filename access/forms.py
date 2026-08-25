"""
Forms for the request and approval screens.

Validation happens twice on purpose. These forms check what they can so the
requester gets a useful message before submitting, and `workflow.submit` and
`workflow.decide` check everything again because the form is a convenience and
the workflow is the control. A request raised through the shell, the read
interface, or a future integration passes through exactly the same gates.
"""

from __future__ import annotations

from django import forms
from django.contrib.auth.models import User

from .models import (
    AccessLevel,
    AccessRequest,
    ApprovalStep,
    Approver,
    Principal,
    Resource,
    max_grant_days,
)
from .workflow import resolve_policy


def identity_for(user: User) -> str:
    """
    The identity a signed-in user acts under.

    Email where there is one, because that is what approver records, resource
    owners, and ticketing systems key on. Falling back to the username means a
    local account still works in a demonstration without silently matching
    somebody else's approver record.
    """
    return (user.email or user.get_username()).strip().lower()


def approver_for(user: User) -> Approver | None:
    return Approver.objects.filter(identifier__iexact=identity_for(user), active=True).first()


def can_decide(user: User, request_object: AccessRequest) -> tuple[bool, str]:
    """
    Whether this user may record a decision, and why not when they may not.

    The message matters: an approver who cannot see why the button is missing
    emails somebody, and that somebody often solves it by loosening the policy.
    """
    from .workflow import SegregationOfDutiesError, check_segregation

    if request_object.state != AccessRequest.State.PENDING:
        return False, f"This request is {request_object.get_state_display().lower()}."
    try:
        check_segregation(request_object, identity_for(user), approver_for(user))
    except SegregationOfDutiesError as exc:
        return False, str(exc)
    return True, ""


class AccessRequestForm(forms.Form):
    """Raise a request for a person or a bot to hold access on a resource."""

    principal = forms.ModelChoiceField(
        queryset=Principal.objects.filter(active=True).order_by("identifier"),
        label="Who needs the access",
        help_text="A developer, or a bot or service identity.",
    )
    resource = forms.ModelChoiceField(
        queryset=Resource.objects.filter(archived=False).order_by("identifier"),
        label="Resource",
    )
    access_level = forms.ChoiceField(choices=AccessLevel.choices, initial=AccessLevel.READ)
    requested_days = forms.IntegerField(
        min_value=0,
        max_value=max_grant_days(),
        required=False,
        label="Days",
        help_text=(
            "Leave blank to take the policy default. Zero requests standing access, "
            "which most policies refuse."
        ),
    )
    ticket_reference = forms.CharField(max_length=80, required=False, label="Change or incident reference")
    justification = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 4}),
        required=False,
        help_text=(
            "What the access is for, in enough detail that a reviewer reading it in six "
            "months can decide whether it is still needed."
        ),
    )

    def clean(self):
        cleaned = super().clean()
        principal = cleaned.get("principal")
        resource = cleaned.get("resource")
        level = cleaned.get("access_level")
        if not (principal and resource and level):
            return cleaned

        policy = resolve_policy(resource, principal, level)
        self.policy = policy

        if policy:
            if policy.require_justification and not (cleaned.get("justification") or "").strip():
                self.add_error("justification", "This resource requires a written justification.")
            if policy.require_ticket_reference and not (cleaned.get("ticket_reference") or "").strip():
                self.add_error("ticket_reference", "This resource requires a change or incident reference.")
            days = cleaned.get("requested_days")
            if days and days > policy.maximum_duration_days:
                self.add_error(
                    "requested_days",
                    f"The ceiling for this resource is {policy.maximum_duration_days} days.",
                )
            if days == 0 and not policy.standing_access_allowed:
                self.add_error("requested_days", "Standing access is not permitted on this resource.")
            if principal.is_non_human and policy.require_owner_for_bots and not principal.responsible_owner:
                self.add_error(
                    "principal",
                    f"{principal} has no responsible human recorded. Name one before requesting access.",
                )

        existing = AccessRequest.objects.filter(
            principal=principal,
            resource=resource,
            access_level=level,
            state__in=[AccessRequest.State.PENDING, AccessRequest.State.APPROVED],
        ).first()
        if existing:
            self.add_error(None, f"{existing.reference} is already open for exactly this access.")
        return cleaned


class DecisionForm(forms.Form):
    decision = forms.ChoiceField(choices=ApprovalStep.Decision.choices)
    comment = forms.CharField(widget=forms.Textarea(attrs={"rows": 3}), required=False)

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("decision") == ApprovalStep.Decision.REJECTED and not (
            cleaned.get("comment") or ""
        ).strip():
            # An unexplained rejection sends the requester back to ask why, and
            # the answer ends up somewhere that is not the record.
            self.add_error("comment", "Say why. The requester will read this.")
        return cleaned


class HandoffForm(forms.Form):
    """Record that provisioning was passed to the system that performs it."""

    handoff_system = forms.CharField(max_length=80, initial="ServiceNow", label="Provisioning system")
    handoff_reference = forms.CharField(max_length=120, label="Task reference")
