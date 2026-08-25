from rest_framework import serializers

from inventory.models import CollectionRun, Finding, LifecycleEvent, ManagedAccount, PamSystem


class PamSystemSerializer(serializers.ModelSerializer):
    collection_overdue = serializers.BooleanField(read_only=True)

    class Meta:
        model = PamSystem
        fields = (
            "id", "name", "vendor", "environment", "enabled",
            "collection_interval_minutes", "last_successful_collection", "collection_overdue",
        )
        # credential_reference is deliberately absent from the read interface.


class ManagedAccountSerializer(serializers.ModelSerializer):
    platform_name = serializers.CharField(source="system.name", read_only=True)
    credential_age_days = serializers.IntegerField(read_only=True)
    days_overdue = serializers.IntegerField(read_only=True)
    rotation_pressure = serializers.FloatField(read_only=True)

    class Meta:
        model = ManagedAccount
        fields = (
            "id", "platform_name", "external_id", "username", "container", "target_address",
            "platform", "kind", "status", "owner_identity", "owner_team", "business_application",
            "onboarded_at", "last_rotation_at", "next_rotation_due", "rotation_interval_days",
            "auto_rotation_enabled", "verification_ok", "consecutive_rotation_failures",
            "last_used_at", "exclusive_checkout", "credential_age_days", "days_overdue",
            "rotation_pressure", "risk_score", "first_seen_at", "last_seen_at",
        )
        # `raw` is excluded: it is scrubbed, but there is no reason to publish
        # vendor internals through a read interface.


class LifecycleEventSerializer(serializers.ModelSerializer):
    account_name = serializers.CharField(source="account.username", read_only=True)
    platform_name = serializers.CharField(source="account.system.name", read_only=True)

    class Meta:
        model = LifecycleEvent
        fields = (
            "id", "kind", "occurred_at", "recorded_at", "actor", "source_address",
            "outcome", "ticket_reference", "detail", "account", "account_name", "platform_name",
        )


class FindingSerializer(serializers.ModelSerializer):
    account_name = serializers.CharField(source="account.username", read_only=True)
    platform_name = serializers.CharField(source="system.name", read_only=True)
    age_days = serializers.IntegerField(read_only=True)

    class Meta:
        model = Finding
        fields = (
            "id", "rule_id", "title", "category", "severity", "state", "opened_at",
            "last_seen_at", "resolved_at", "age_days", "assigned_to", "ticket_reference",
            "evidence", "account", "account_name", "platform_name",
        )
        read_only_fields = ("rule_id", "title", "category", "severity", "opened_at", "evidence")


class CollectionRunSerializer(serializers.ModelSerializer):
    duration_seconds = serializers.FloatField(read_only=True)

    class Meta:
        model = CollectionRun
        fields = "__all__"
