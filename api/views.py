"""
Read interface for downstream consumers: the enterprise Security Information
and Event Management platform, governance-risk-compliance tooling, and the
recertification workflow.

Writes are limited to finding triage (acknowledge, suppress, assign). Nothing
here can alter collected inventory, because the vault is the system of record.
"""

from __future__ import annotations

from django.utils import timezone
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import mixins, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from inventory.models import CollectionRun, Finding, LifecycleEvent, ManagedAccount, PamSystem

from .serializers import (
    CollectionRunSerializer,
    FindingSerializer,
    LifecycleEventSerializer,
    ManagedAccountSerializer,
    PamSystemSerializer,
)


class ReadOnlyViewSet(viewsets.ReadOnlyModelViewSet):
    filter_backends = [DjangoFilterBackend]


class PamSystemViewSet(ReadOnlyViewSet):
    queryset = PamSystem.objects.all()
    serializer_class = PamSystemSerializer
    filterset_fields = ["vendor", "environment", "enabled"]


class ManagedAccountViewSet(ReadOnlyViewSet):
    queryset = ManagedAccount.objects.select_related("system").all()
    serializer_class = ManagedAccountSerializer
    filterset_fields = {
        "system": ["exact"],
        "kind": ["exact", "in"],
        "status": ["exact"],
        "auto_rotation_enabled": ["exact"],
        "owner_identity": ["exact", "icontains"],
        "container": ["exact", "icontains"],
        "last_rotation_at": ["lt", "gt", "isnull"],
        "risk_score": ["gte", "lte"],
    }

    @action(detail=True, methods=["get"])
    def timeline(self, request, pk=None):
        account = self.get_object()
        events = account.events.order_by("-occurred_at")[:500]
        return Response(LifecycleEventSerializer(events, many=True).data)


class LifecycleEventViewSet(ReadOnlyViewSet):
    queryset = LifecycleEvent.objects.select_related("account", "account__system").all()
    serializer_class = LifecycleEventSerializer
    filterset_fields = {
        "kind": ["exact", "in"],
        "occurred_at": ["gte", "lte"],
        "actor": ["exact", "icontains"],
        "outcome": ["exact"],
    }


class FindingViewSet(
    mixins.UpdateModelMixin,
    ReadOnlyViewSet,
):
    queryset = Finding.objects.select_related("account", "system").all()
    serializer_class = FindingSerializer
    filterset_fields = {
        "rule_id": ["exact", "in"],
        "severity": ["exact", "in"],
        "state": ["exact", "in"],
        "category": ["exact"],
        "system": ["exact"],
        "opened_at": ["gte", "lte"],
    }

    @action(detail=True, methods=["post"])
    def acknowledge(self, request, pk=None):
        finding = self.get_object()
        finding.state = Finding.State.ACKNOWLEDGED
        finding.assigned_to = request.data.get("assigned_to") or request.user.get_username()
        finding.ticket_reference = request.data.get("ticket_reference", finding.ticket_reference)
        finding.exported_at = None
        finding.save()
        return Response(self.get_serializer(finding).data)

    @action(detail=True, methods=["post"])
    def suppress(self, request, pk=None):
        """
        Suppression is time-boxed on purpose. An indefinite exception is how a
        rotation gap survives three audit cycles.
        """
        finding = self.get_object()
        days = int(request.data.get("days", 30))
        finding.state = Finding.State.SUPPRESSED
        finding.suppressed_until = timezone.now() + timezone.timedelta(days=min(days, 180))
        finding.suppression_reason = request.data.get("reason", "")
        finding.assigned_to = request.user.get_username()
        finding.save()
        return Response(self.get_serializer(finding).data)


class CollectionRunViewSet(ReadOnlyViewSet):
    queryset = CollectionRun.objects.select_related("system").all()
    serializer_class = CollectionRunSerializer
    filterset_fields = ["system", "outcome"]
