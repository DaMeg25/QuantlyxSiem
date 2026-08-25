from __future__ import annotations

from datetime import timedelta

from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Case, Count, F, IntegerField, Q, Value, When
from django.db.models.functions import TruncDate
from django.shortcuts import get_object_or_404, render
from django.utils import timezone

from access.models import (
    AccessGrant,
    AccessLevel,
    AccessRequest,
    ELEVATED_LEVELS,
    Principal,
    Resource,
)
from connectors.base import Capability
from connectors.registry import capabilities_for, catalogue
from rules.engine import RuleEngine

from inventory.models import (
    AssetType,
    CredentialAssetLink,
    TargetAsset,
    TelemetrySource,
    UsageObservation,
    AccountKind,
    AccountStatus,
    CollectionRun,
    DiscoveredAccount,
    Finding,
    LifecycleEvent,
    ManagedAccount,
    NON_HUMAN_KINDS,
    PamSystem,
    SEVERITY_ORDER,
    Severity,
)

AGE_BANDS = (
    ("0-30", 0, 30),
    ("31-60", 31, 60),
    ("61-90", 61, 90),
    ("91-180", 91, 180),
    ("181-365", 181, 365),
    ("365+", 366, 100_000),
)


def _severity_counts(queryset):
    counts = {choice.value: 0 for choice in Severity}
    for row in queryset.values("severity").annotate(count=Count("id")):
        counts[row["severity"]] = row["count"]
    return counts


def _age_histogram():
    now = timezone.now()
    buckets = []
    for label, low, high in AGE_BANDS:
        upper = now - timedelta(days=low)
        lower = now - timedelta(days=high)
        count = ManagedAccount.objects.live().filter(
            status=AccountStatus.ACTIVE, last_rotation_at__lte=upper, last_rotation_at__gt=lower
        ).count()
        buckets.append({"label": label, "count": count, "overdue": low >= 91})
    never = ManagedAccount.objects.live().filter(
        status=AccountStatus.ACTIVE, last_rotation_at__isnull=True
    ).count()
    buckets.append({"label": "never", "count": never, "overdue": True})
    peak = max((bucket["count"] for bucket in buckets), default=0) or 1
    for bucket in buckets:
        bucket["percent"] = round(bucket["count"] / peak * 100, 1)
    return buckets


@login_required
def overview(request):
    live = ManagedAccount.objects.live()
    active = live.filter(status=AccountStatus.ACTIVE)
    open_findings = Finding.objects.filter(state__in=[Finding.State.OPEN, Finding.State.ACKNOWLEDGED])

    non_human = active.filter(kind__in=NON_HUMAN_KINDS)
    unmanaged_non_human = non_human.filter(
        Q(auto_rotation_enabled=False) | Q(last_rotation_at__isnull=True)
    )

    overdue = active.annotate(
        interval=Case(
            When(rotation_interval_days__isnull=False, then=F("rotation_interval_days")),
            default=Value(90),
            output_field=IntegerField(),
        )
    ).filter(
        Q(next_rotation_due__lt=timezone.now())
        | Q(next_rotation_due__isnull=True, last_rotation_at__lt=timezone.now() - timedelta(days=90))
        | Q(last_rotation_at__isnull=True)
    )

    kind_breakdown = list(
        active.values("kind").annotate(count=Count("id")).order_by("-count")
    )
    kind_total = sum(row["count"] for row in kind_breakdown) or 1
    for row in kind_breakdown:
        row["label"] = AccountKind(row["kind"]).label
        row["percent"] = round(row["count"] / kind_total * 100, 1)

    top_findings = sorted(
        open_findings.select_related("account", "system")[:400],
        key=lambda finding: (SEVERITY_ORDER.get(finding.severity, 9), -finding.age_days),
    )[:12]

    # Group on the rule, not the per-finding title: titles carry evidence
    # ("overdue by 634 days"), so grouping on them turns one rule into a row per
    # account. The static condition text comes from the rule class.
    rule_titles = {cls.rule_id: cls.title for cls in RuleEngine().rule_classes}
    rule_rollup = list(
        open_findings.values("rule_id", "severity", "category")
        .annotate(count=Count("id"))
        .order_by("-count")[:12]
    )
    for row in rule_rollup:
        row["title"] = rule_titles.get(row["rule_id"], row["rule_id"])
    rule_rollup.sort(key=lambda row: (SEVERITY_ORDER.get(row["severity"], 9), -row["count"]))

    recent_events = (
        LifecycleEvent.objects.select_related("account", "account__system")
        .exclude(kind=LifecycleEvent.Kind.VENDOR_AUDIT)
        .order_by("-occurred_at")[:15]
    )

    platforms = []
    for system in PamSystem.objects.filter(enabled=True):
        last_run = system.runs.first()
        platforms.append(
            {
                "system": system,
                "accounts": live.filter(system=system).count(),
                "open_findings": open_findings.filter(system=system).count(),
                "last_run": last_run,
                "stale": system.collection_overdue,
            }
        )

    context = {
        "page": "overview",
        "total_accounts": live.count(),
        "active_accounts": active.count(),
        "non_human_count": non_human.count(),
        "non_human_ungoverned": unmanaged_non_human.count(),
        "overdue_count": overdue.count(),
        "overdue_percent": round(overdue.count() / max(active.count(), 1) * 100, 1),
        "median_age_days": _median_credential_age(active),
        "severity_counts": _severity_counts(open_findings),
        "open_finding_count": open_findings.count(),
        "age_histogram": _age_histogram(),
        "kind_breakdown": kind_breakdown,
        "top_findings": top_findings,
        "rule_rollup": rule_rollup,
        "recent_events": recent_events,
        "platforms": platforms,
        "unvaulted_count": DiscoveredAccount.objects.filter(onboarded=False).count(),
    }
    return render(request, "dashboard/overview.html", context)


def _median_credential_age(queryset) -> int:
    ages = sorted(
        account.credential_age_days
        for account in queryset.only("last_rotation_at")
        if account.credential_age_days is not None
    )
    if not ages:
        return 0
    middle = len(ages) // 2
    if len(ages) % 2:
        return ages[middle]
    return (ages[middle - 1] + ages[middle]) // 2


@login_required
def accounts(request):
    queryset = ManagedAccount.objects.live().select_related("system")

    filters = {
        "kind": request.GET.get("kind", ""),
        "status": request.GET.get("status", ""),
        "system": request.GET.get("system", ""),
        "posture": request.GET.get("posture", ""),
        "q": request.GET.get("q", "").strip(),
    }
    if filters["kind"]:
        queryset = queryset.filter(kind=filters["kind"])
    if filters["status"]:
        queryset = queryset.filter(status=filters["status"])
    if filters["system"]:
        queryset = queryset.filter(system_id=filters["system"])
    if filters["posture"] == "overdue":
        queryset = queryset.filter(
            Q(next_rotation_due__lt=timezone.now()) | Q(last_rotation_at__isnull=True)
        )
    elif filters["posture"] == "unrotated_bots":
        queryset = queryset.filter(kind__in=NON_HUMAN_KINDS).filter(
            Q(auto_rotation_enabled=False) | Q(last_rotation_at__isnull=True)
        )
    elif filters["posture"] == "ownerless":
        queryset = queryset.filter(owner_identity="", owner_team="")
    if filters["q"]:
        term = filters["q"]
        queryset = queryset.filter(
            Q(username__icontains=term)
            | Q(target_address__icontains=term)
            | Q(container__icontains=term)
            | Q(owner_identity__icontains=term)
            | Q(business_application__icontains=term)
        )

    queryset = queryset.order_by("-risk_score", "username")
    page = Paginator(queryset, 60).get_page(request.GET.get("page"))

    return render(
        request,
        "dashboard/accounts.html",
        {
            "page": "accounts",
            "rows": page,
            "filters": filters,
            "systems": PamSystem.objects.all(),
            "kinds": AccountKind.choices,
            "statuses": AccountStatus.choices,
            "result_count": queryset.count(),
        },
    )


@login_required
def findings(request):
    state = request.GET.get("state", "open")
    queryset = Finding.objects.select_related("account", "system")
    if state == "open":
        queryset = queryset.filter(state__in=[Finding.State.OPEN, Finding.State.ACKNOWLEDGED])
    elif state != "all":
        queryset = queryset.filter(state=state)

    severity = request.GET.get("severity", "")
    if severity:
        queryset = queryset.filter(severity=severity)
    rule_id = request.GET.get("rule_id", "")
    if rule_id:
        queryset = queryset.filter(rule_id=rule_id)

    ordered = sorted(
        queryset[:1000], key=lambda finding: (SEVERITY_ORDER.get(finding.severity, 9), -finding.age_days)
    )
    page = Paginator(ordered, 50).get_page(request.GET.get("page"))

    return render(
        request,
        "dashboard/findings.html",
        {
            "page": "findings",
            "rows": page,
            "state": state,
            "severity": severity,
            "rule_id": rule_id,
            "severities": Severity.choices,
            "rule_ids": Finding.objects.values_list("rule_id", flat=True).distinct().order_by("rule_id"),
        },
    )


@login_required
def account_detail(request, pk: int):
    account = get_object_or_404(
        ManagedAccount.objects.select_related("system"), pk=pk
    )
    events = account.events.order_by("-occurred_at")[:100]
    rotation_history = (
        account.events.filter(kind=LifecycleEvent.Kind.ROTATED)
        .annotate(day=TruncDate("occurred_at"))
        .order_by("-occurred_at")[:24]
    )
    reach = (
        account.asset_links.select_related("asset").order_by("-last_seen_at")[:40]
    )
    recent_usage = (
        account.usage.select_related("asset", "source").order_by("-occurred_at")[:25]
    )
    unexplained = account.usage.filter(
        correlation=UsageObservation.Correlation.UNEXPLAINED
    ).count()

    return render(
        request,
        "dashboard/account_detail.html",
        {
            "page": "accounts",
            "account": account,
            "events": events,
            "rotation_history": rotation_history,
            "reach": reach,
            "recent_usage": recent_usage,
            "unexplained_usage": unexplained,
            "open_findings": account.findings.filter(
                state__in=[Finding.State.OPEN, Finding.State.ACKNOWLEDGED]
            ),
            "snapshots": account.snapshots.all()[:30],
        },
    )


@login_required
def coverage(request):
    """
    Which detections are live on which platform, and which are inert.

    This is the page to open before telling anyone the estate is clean. A rule
    that cannot run on a platform produces exactly the same empty result as a
    rule that ran and found nothing, and the difference matters.
    """
    systems = list(PamSystem.objects.filter(enabled=True))
    system_capabilities = {system.pk: capabilities_for(system) for system in systems}

    matrix = []
    for rule_class in RuleEngine().rule_classes:
        cells = []
        for system in systems:
            missing = sorted(set(rule_class.requires) - system_capabilities[system.pk])
            cells.append(
                {
                    "system": system,
                    "supported": not missing,
                    "missing": missing,
                    "open_findings": Finding.objects.filter(
                        rule_id=rule_class.rule_id,
                        system=system,
                        state__in=[Finding.State.OPEN, Finding.State.ACKNOWLEDGED],
                    ).count(),
                }
            )
        matrix.append(
            {
                "rule_id": rule_class.rule_id,
                "title": rule_class.title,
                "severity": rule_class.severity,
                "requires": sorted(rule_class.requires),
                "cells": cells,
                "live_on": sum(1 for cell in cells if cell["supported"]),
                "total": len(cells),
            }
        )

    capability_rows = []
    for capability in Capability.ALL:
        supplied = [system for system in systems if capability in system_capabilities[system.pk]]
        capability_rows.append(
            {
                "capability": capability,
                "supplied_by": [system.name for system in supplied],
                "count": len(supplied),
                "total": len(systems),
            }
        )

    return render(
        request,
        "dashboard/coverage.html",
        {
            "page": "coverage",
            "systems": systems,
            "matrix": matrix,
            "capability_rows": capability_rows,
            "catalogue": catalogue(),
            "inert_rules": [row for row in matrix if row["live_on"] == 0],
        },
    )


@login_required
def usage(request):
    """
    Where credentials have actually been used, and which logins nothing explains.

    Two questions on one page. Blast radius answers "if this one credential
    leaked, what does it open" -- the number that decides how hard a rotation is
    and how bad a compromise would be. The unexplained feed answers "which
    privileged logins did not come from the vault", which is the same thing as
    asking where working copies of managed credentials are living.
    """
    window = int(request.GET.get("days", 30))
    since = timezone.now() - timedelta(days=window)

    observations = UsageObservation.objects.filter(occurred_at__gte=since)
    by_mechanism = list(
        observations.values("mechanism").annotate(count=Count("id")).order_by("-count")
    )
    mechanism_total = sum(row["count"] for row in by_mechanism) or 1
    for row in by_mechanism:
        row["percent"] = round(row["count"] / mechanism_total * 100, 1)
        row["label"] = dict(UsageObservation.Mechanism.choices).get(row["mechanism"], row["mechanism"])

    correlation_counts = {
        row["correlation"]: row["count"]
        for row in observations.values("correlation").annotate(count=Count("id"))
    }

    blast_radius = (
        CredentialAssetLink.objects.filter(last_seen_at__gte=since)
        .values("account_id")
        .annotate(assets=Count("asset_id"), observations=Count("observation_count"))
        .order_by("-assets")[:20]
    )
    radius_rows = []
    for row in blast_radius:
        account = ManagedAccount.objects.select_related("system").filter(pk=row["account_id"]).first()
        if not account:
            continue
        links = list(account.asset_links.select_related("asset").order_by("-last_seen_at"))
        radius_rows.append(
            {
                "account": account,
                "asset_count": len(links),
                "asset_types": sorted({link.asset.get_asset_type_display() for link in links}),
                "outside_scope": sum(1 for link in links if link.outside_mapped_scope),
                "unexplained": sum(link.unexplained_count for link in links),
                "sample": [link.asset for link in links[:6]],
            }
        )

    unexplained = (
        observations.filter(correlation=UsageObservation.Correlation.UNEXPLAINED)
        .select_related("account", "account__system", "asset", "source")
        .order_by("-occurred_at")[:40]
    )
    unmanaged = (
        observations.filter(correlation=UsageObservation.Correlation.UNMATCHED_ACCOUNT)
        .values("observed_account_name")
        .annotate(count=Count("id"), assets=Count("asset_id", distinct=True))
        .order_by("-count")[:15]
    )

    asset_rows = (
        TargetAsset.objects.filter(usage__occurred_at__gte=since)
        .annotate(credentials=Count("account_links__account_id", distinct=True), logins=Count("usage"))
        .order_by("-credentials")[:15]
    )

    return render(
        request,
        "dashboard/usage.html",
        {
            "page": "usage",
            "window": window,
            "sources": TelemetrySource.objects.all(),
            "by_mechanism": by_mechanism,
            "correlation_counts": correlation_counts,
            "observation_total": observations.count(),
            "radius_rows": radius_rows,
            "unexplained": unexplained,
            "unmanaged": unmanaged,
            "asset_rows": asset_rows,
            "asset_total": TargetAsset.objects.count(),
        },
    )


@login_required
def access(request):
    """
    Who holds what, on whose authority, and until when.

    Ordered by what an examiner asks first: the pending queue, then the two
    reconciliation residues -- access with no approval behind it, and access
    that expired on paper and not in reality.
    """
    grants = AccessGrant.objects.filter(revoked_at__isnull=True, absent_since__isnull=True)
    elevated = [level.value for level in ELEVATED_LEVELS]

    pending = (
        AccessRequest.objects.filter(state=AccessRequest.State.PENDING)
        .select_related("principal", "resource", "policy")
        .order_by("created_at")[:25]
    )
    unapproved = (
        grants.filter(origin=AccessGrant.Origin.DISCOVERED, access_level__in=elevated)
        .select_related("principal", "resource")
        .order_by("-resource__production", "resource__identifier")[:30]
    )
    from access.reconcile import stale_expiries

    overdue = stale_expiries()[:25]

    standing = (
        grants.filter(expires_at__isnull=True, access_level__in=elevated, resource__production=True)
        .select_related("principal", "resource")[:25]
    )

    by_level = list(grants.values("access_level").annotate(count=Count("id")).order_by("-count"))
    level_total = sum(row["count"] for row in by_level) or 1
    for row in by_level:
        row["percent"] = round(row["count"] / level_total * 100, 1)
        row["elevated"] = row["access_level"] in elevated

    bots = Principal.objects.filter(principal_type__in=["bot", "service"])
    bot_grants = grants.filter(principal__in=bots, access_level__in=elevated)

    return render(
        request,
        "dashboard/access.html",
        {
            "page": "access",
            "resource_count": Resource.objects.filter(archived=False).count(),
            "production_count": Resource.objects.filter(production=True, archived=False).count(),
            "grant_count": grants.count(),
            "elevated_count": grants.filter(access_level__in=elevated).count(),
            "unapproved_count": grants.filter(origin=AccessGrant.Origin.DISCOVERED).count(),
            "overdue_count": len(stale_expiries()),
            "bot_count": bots.count(),
            "bot_elevated": bot_grants.count(),
            "bot_ownerless": bot_grants.filter(principal__responsible_owner="").count(),
            "pending": pending,
            "unapproved": unapproved,
            "overdue": overdue,
            "standing": standing,
            "by_level": by_level,
            "recent_decisions": (
                AccessRequest.objects.exclude(decided_at__isnull=True)
                .select_related("principal", "resource")
                .order_by("-decided_at")[:12]
            ),
        },
    )
