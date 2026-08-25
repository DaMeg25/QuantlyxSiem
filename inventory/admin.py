from django import forms
from django.contrib import admin

from connectors.registry import catalogue, vendor_choices

from .models import (
    TelemetrySource,
    AccountSnapshot,
    CollectionRun,
    DiscoveredAccount,
    Finding,
    LifecycleEvent,
    ManagedAccount,
    PamSystem,
    RuleConfiguration,
)


class PamSystemForm(forms.ModelForm):
    """Vendor is a dropdown built from the live connector registry, so a newly
    installed connector appears here without a migration or a code change."""

    class Meta:
        model = PamSystem
        fields = "__all__"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        choices = vendor_choices()
        current = self.instance.vendor if self.instance and self.instance.pk else None
        if current and current not in dict(choices):
            # The connector that produced this row is no longer installed. Keep
            # the value visible rather than silently rewriting configuration.
            choices = [(current, f"{current} (connector not installed)")] + choices
        self.fields["vendor"] = forms.ChoiceField(
            choices=choices,
            help_text="Registered connectors. Run 'manage.py list_connectors' to see what each supplies.",
        )


@admin.register(PamSystem)
class PamSystemAdmin(admin.ModelAdmin):
    form = PamSystemForm
    list_display = ("name", "vendor", "environment", "enabled", "capability_summary", "last_successful_collection")
    list_filter = ("vendor", "environment", "enabled")
    search_fields = ("name", "base_url")
    readonly_fields = ("last_successful_collection", "capabilities", "connector_notes")

    @admin.display(description="Supplies")
    def capability_summary(self, obj):
        return ", ".join(obj.capabilities or []) or "not yet collected"

    @admin.display(description="Connector")
    def connector_notes(self, obj):
        for entry in catalogue():
            if entry["vendor"] == obj.vendor:
                lines = [entry["display_name"], entry["class_path"]]
                if entry["required_credentials"]:
                    lines.append("Credential keys: " + ", ".join(entry["required_credentials"]))
                if entry["specification_driven"]:
                    lines.append("Specification driven: configure options['spec'].")
                if entry["documentation"]:
                    lines.append(entry["documentation"])
                return " | ".join(lines)
        return "No connector registered for this vendor key."
    fieldsets = (
        (None, {"fields": ("name", "vendor", "base_url", "environment", "enabled")}),
        (
            "Collector identity",
            {
                "fields": ("credential_reference",),
                "description": (
                    "A pointer only, such as env:PAM_CYBERARK_PROD or "
                    "file:/run/secrets/cyberark.json. Never paste a credential here."
                ),
            },
        ),
        ("Behaviour", {"fields": ("options", "collection_interval_minutes", "notes")}),
        ("State", {"fields": ("last_successful_collection", "capabilities", "connector_notes")}),
    )


@admin.register(ManagedAccount)
class ManagedAccountAdmin(admin.ModelAdmin):
    list_display = ("username", "system", "container", "kind", "status", "last_rotation_at", "risk_score")
    list_filter = ("system", "kind", "status", "auto_rotation_enabled")
    search_fields = ("username", "container", "target_address", "owner_identity", "business_application")
    readonly_fields = [field.name for field in ManagedAccount._meta.fields]

    def has_add_permission(self, request):
        return False  # inventory is collected, never typed


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ("rule_id", "severity", "state", "account", "opened_at", "assigned_to")
    list_filter = ("severity", "state", "rule_id", "system")
    search_fields = ("account__username", "ticket_reference", "assigned_to")
    actions = ["acknowledge"]

    @admin.action(description="Acknowledge selected findings")
    def acknowledge(self, request, queryset):
        queryset.update(state=Finding.State.ACKNOWLEDGED, assigned_to=request.user.get_username())


@admin.register(RuleConfiguration)
class RuleConfigurationAdmin(admin.ModelAdmin):
    list_display = ("rule_id", "enabled", "severity_override", "updated_at", "updated_by")
    list_filter = ("enabled",)

    def save_model(self, request, obj, form, change):
        obj.updated_by = request.user.get_username()
        super().save_model(request, obj, form, change)


@admin.register(CollectionRun)
class CollectionRunAdmin(admin.ModelAdmin):
    list_display = ("system", "started_at", "outcome", "accounts_seen", "accounts_created", "accounts_retired")
    list_filter = ("outcome", "system")


@admin.register(LifecycleEvent)
class LifecycleEventAdmin(admin.ModelAdmin):
    list_display = ("occurred_at", "kind", "account", "actor", "outcome")
    list_filter = ("kind", "outcome")
    search_fields = ("account__username", "actor")


admin.site.register(AccountSnapshot)
admin.site.register(DiscoveredAccount)

admin.site.site_header = "Quantlyx · credential lifecycle"
admin.site.site_title = "Quantlyx"
admin.site.index_title = "Configuration"


class TelemetrySourceForm(forms.ModelForm):
    """Collector choices come from the live registry, as with connectors."""

    class Meta:
        model = TelemetrySource
        fields = "__all__"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from usage.collectors import collector_choices

        self.fields["collector"] = forms.ChoiceField(
            choices=collector_choices(),
            required=False,
            help_text=(
                "Leave blank if the enterprise event platform delivers this feed as files. "
                "Pick a collector to pull it directly."
            ),
        )


@admin.register(TelemetrySource)
class TelemetrySourceAdmin(admin.ModelAdmin):
    form = TelemetrySourceForm
    list_display = ("name", "kind", "collector", "enabled", "last_ingest_at", "records_ingested")
    list_filter = ("kind", "enabled")
    readonly_fields = ("last_ingest_at", "records_ingested", "cursor")
    fieldsets = (
        (None, {"fields": ("name", "kind", "enabled", "expected_interval_minutes", "notes")}),
        (
            "Delivered as files",
            {"fields": ("ingest_reference",),
             "description": "Path or glob the event platform writes exports to."},
        ),
        (
            "Pulled directly",
            {"fields": ("collector", "settings", "credential_reference"),
             "description": (
                 "credential_reference is a pointer such as env:ISE_DATA_CONNECT. "
                 "Never paste a credential here."
             )},
        ),
        ("State", {"fields": ("last_ingest_at", "records_ingested", "cursor")}),
    )
