"""Celery tasks: collect, evaluate, export. Also runnable as management commands."""

from __future__ import annotations

import logging
from datetime import timedelta

from celery import shared_task
from django.conf import settings
from django.utils import timezone

from connectors.registry import build_connector
from inventory.models import CollectionRun, LifecycleEvent, PamSystem

from .reconcile import ingest_activity, reconcile_accounts

log = logging.getLogger(__name__)


@shared_task(name="collection.collect_all")
def collect_all() -> dict[str, str]:
    results = {}
    for system in PamSystem.objects.filter(enabled=True):
        if system.last_successful_collection:
            due = system.last_successful_collection + timedelta(
                minutes=system.collection_interval_minutes
            )
            if timezone.now() < due:
                results[system.name] = "not_due"
                continue
        collect_system.delay(system.pk)
        results[system.name] = "queued"
    return results


@shared_task(name="collection.collect_system", bind=True, max_retries=2, default_retry_delay=300)
def collect_system(self, system_id: int) -> str:
    system = PamSystem.objects.get(pk=system_id)
    run = CollectionRun.objects.create(system=system)
    try:
        with build_connector(system) as connector:
            capabilities = sorted(connector.declared_capabilities())
            if capabilities != (system.capabilities or []):
                system.capabilities = capabilities
                system.save(update_fields=["capabilities"])

            reconcile_accounts(system, run, connector.iter_accounts())

            since = system.last_successful_collection or timezone.now() - timedelta(days=7)
            ingested = ingest_activity(system, connector.iter_activity(since))
            run.activities_ingested = ingested

            # Tier one and two of the usage picture: sessions the vault brokered
            # and credential fetches by named applications. Tier three arrives
            # separately, from the targets themselves.
            if "session_targets" in capabilities or "application_identity" in capabilities:
                _ingest_usage(system, connector, since)

        run.outcome = CollectionRun.Outcome.SUCCESS
        run.finished_at = timezone.now()
        run.save()
        system.last_successful_collection = run.finished_at
        system.save(update_fields=["last_successful_collection"])
        correlate_usage.delay()
        evaluate_rules.delay(system_id=system.pk)
        return "success"
    except Exception as exc:  # noqa: BLE001 -- the run row is the error channel
        log.exception("Collection failed for %s", system.name)
        run.outcome = CollectionRun.Outcome.FAILED
        run.finished_at = timezone.now()
        run.error_message = f"{type(exc).__name__}: {exc}"[:4000]
        run.save()
        raise self.retry(exc=exc)


@shared_task(name="collection.evaluate_rules")
def evaluate_rules(system_id: int | None = None) -> dict[str, int]:
    from rules.engine import RuleEngine

    engine = RuleEngine()
    return engine.run(system_id=system_id)


@shared_task(name="collection.export_pending")
def export_pending() -> dict[str, int]:
    from export.splunk_hec import export_findings, export_lifecycle_events

    return {
        "events": export_lifecycle_events(),
        "findings": export_findings(),
    }


@shared_task(name="collection.prune_history")
def prune_history() -> dict[str, int]:
    """Snapshots grow fast. Keep the retention window the compliance team agreed to."""
    from inventory.models import AccountSnapshot

    days = getattr(settings, "SNAPSHOT_RETENTION_DAYS", 400)
    cutoff = timezone.now() - timedelta(days=days)
    snapshots, _ = AccountSnapshot.objects.filter(captured_at__lt=cutoff).delete()
    event_days = getattr(settings, "EVENT_RETENTION_DAYS", 730)
    events, _ = LifecycleEvent.objects.filter(
        occurred_at__lt=timezone.now() - timedelta(days=event_days),
        exported_at__isnull=False,
    ).delete()

    # Usage observations are by far the largest table: one row per privileged
    # login across the whole estate. The durable value is already rolled up into
    # CredentialAssetLink and forwarded downstream, so the raw rows have a much
    # shorter life than the inventory they describe.
    from inventory.models import UsageObservation

    usage_days = getattr(settings, "USAGE_RETENTION_DAYS", 120)
    usage, _ = UsageObservation.objects.filter(
        occurred_at__lt=timezone.now() - timedelta(days=usage_days),
        exported_at__isnull=False,
    ).delete()
    return {
        "snapshots_deleted": snapshots,
        "events_deleted": events,
        "usage_deleted": usage,
    }


def _ingest_usage(system, connector, since) -> int:
    """Store brokered sessions as usage observations against the right asset."""
    from inventory.models import ManagedAccount, UsageObservation
    from usage.correlate import record_observations

    index = {
        account.external_id: account
        for account in ManagedAccount.objects.filter(system=system).only("id", "external_id")
    }
    rows = []
    for record in connector.iter_usage(since):
        account = index.get(record.account_external_id)
        rows.append(
            {
                "observed_account_name": account.username if account else record.account_external_id,
                "asset_identifier": record.asset_identifier,
                "asset_hint": record.asset_hint,
                "occurred_at": record.occurred_at,
                "ended_at": record.ended_at,
                "mechanism": record.mechanism,
                "actor": record.actor,
                "source_address": record.source_address,
                "outcome": record.outcome,
                "session_reference": record.session_reference,
                "command_count": record.command_count,
                "dedupe_key": f"{system.pk}:{record.external_id}",
                "detail": {"vendor_session": True},
            }
        )
    return record_observations(rows)


@shared_task(name="collection.correlate_usage")
def correlate_usage() -> dict:
    from usage.correlate import correlate

    return correlate()
