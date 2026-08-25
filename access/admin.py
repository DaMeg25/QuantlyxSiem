from django.contrib import admin

from .models import (
    AccessGrant,
    AccessRequest,
    AccessReview,
    AccessReviewItem,
    ApprovalPolicy,
    ApprovalStep,
    Approver,
    Principal,
    Resource,
)


class ApprovalStepInline(admin.TabularInline):
    model = ApprovalStep
    extra = 0
    readonly_fields = ("sequence", "approver_identity", "decision", "comment",
                       "decided_at", "previous_hash", "content_hash")

    def has_add_permission(self, request, obj=None):
        # Decisions are recorded through the workflow, which enforces
        # segregation of duties and chains the hash. Typing one in here would
        # produce a record that looks identical and proves nothing.
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(Resource)
class ResourceAdmin(admin.ModelAdmin):
    list_display = ("identifier", "platform", "criticality", "production", "owner_team",
                    "archived", "last_reconciled_at")
    list_filter = ("platform", "criticality", "production", "archived")
    search_fields = ("identifier", "display_name", "owner_identity", "business_application")


@admin.register(Principal)
class PrincipalAdmin(admin.ModelAdmin):
    list_display = ("identifier", "principal_type", "responsible_owner", "team",
                    "managed_account", "active")
    list_filter = ("principal_type", "active")
    search_fields = ("identifier", "display_name", "email", "responsible_owner")
    autocomplete_fields = ()


@admin.register(ApprovalPolicy)
class ApprovalPolicyAdmin(admin.ModelAdmin):
    list_display = ("name", "platform", "approvals_required", "maximum_duration_days",
                    "standing_access_allowed", "enabled")
    list_filter = ("enabled", "platform", "standing_access_allowed")
    fieldsets = (
        (None, {"fields": ("name", "enabled", "notes")}),
        ("Applies to", {"fields": ("resource", "platform", "applies_to_production_only",
                                   "minimum_criticality", "access_levels", "principal_types")}),
        ("Requires", {"fields": ("approvals_required", "approver_groups", "require_resource_owner",
                                 "require_ticket_reference", "require_justification",
                                 "require_owner_for_bots")}),
        ("Limits", {"fields": ("maximum_duration_days", "standing_access_allowed")}),
    )


@admin.register(AccessRequest)
class AccessRequestAdmin(admin.ModelAdmin):
    list_display = ("reference", "principal", "resource", "access_level", "state",
                    "created_at", "expires_at")
    list_filter = ("state", "access_level", "resource__platform")
    search_fields = ("reference", "principal__identifier", "resource__identifier", "ticket_reference")
    inlines = [ApprovalStepInline]
    readonly_fields = ("reference", "created_at", "decided_at", "provisioned_at", "chain_status")

    @admin.display(description="Approval chain")
    def chain_status(self, obj):
        from .workflow import verify_chain

        intact, message = verify_chain(obj)
        return ("intact: " if intact else "BROKEN: ") + message


@admin.register(AccessGrant)
class AccessGrantAdmin(admin.ModelAdmin):
    list_display = ("principal", "resource", "access_level", "origin", "expires_at",
                    "last_confirmed_at", "absent_since")
    list_filter = ("origin", "access_level", "resource__platform", "resource__production")
    search_fields = ("principal__identifier", "resource__identifier")

    def has_add_permission(self, request):
        return False  # grants are reconciled from the platform, never typed


@admin.register(Approver)
class ApproverAdmin(admin.ModelAdmin):
    list_display = ("identifier", "display_name", "team", "independent", "active")
    list_filter = ("active", "independent")
    search_fields = ("identifier", "display_name")


admin.site.register(AccessReview)
admin.site.register(AccessReviewItem)
