"""
Forward normalized events and findings to the enterprise Security Information
and Event Management platform over the Splunk HTTP Event Collector.

The payload is deliberately flat and stable: downstream correlation searches
should never have to know which Privileged Access Management vendor produced a
record. Swap this module for a syslog or Kafka writer if that is the transport
your platform team standardized on -- the calling contract is the two functions
at the bottom.
"""

from __future__ import annotations

import json
import logging

import requests
from django.conf import settings
from django.utils import timezone

from connectors.registry import resolve_credentials
from inventory.models import Finding, LifecycleEvent

log = logging.getLogger(__name__)

BATCH_SIZE = 500


def _session() -> tuple[requests.Session, str] | tuple[None, None]:
    if not settings.SPLUNK_HEC_URL or not settings.SPLUNK_HEC_TOKEN_REFERENCE:
        return None, None
    token = resolve_credentials(settings.SPLUNK_HEC_TOKEN_REFERENCE).get("token")
    if not token:
        log.error("HTTP Event Collector token reference contains no 'token' key")
        return None, None
    session = requests.Session()
    session.headers.update({"Authorization": f"Splunk {token}"})
    session.verify = settings.SPLUNK_HEC_VERIFY
    return session, settings.SPLUNK_HEC_URL


def _envelope(event: dict, source: str) -> dict:
    return {
        "time": event.pop("_epoch"),
        "host": event.pop("_host", "pam-lifecycle-collector"),
        "source": source,
        "sourcetype": settings.SPLUNK_HEC_SOURCETYPE,
        "index": settings.SPLUNK_HEC_INDEX,
        "event": event,
    }


def _ship(session: requests.Session, url: str, envelopes: list[dict]) -> bool:
    body = "".join(json.dumps(item, default=str) for item in envelopes)
    response = session.post(url, data=body, timeout=30)
    if response.status_code >= 400:
        log.error("Event collector rejected batch: %s %s", response.status_code, response.text[:300])
        return False
    return True


def export_lifecycle_events() -> int:
    session, url = _session()
    if not session:
        return 0
    queryset = (
        LifecycleEvent.objects.filter(exported_at__isnull=True)
        .select_related("account", "account__system")
        .order_by("occurred_at")[:BATCH_SIZE]
    )
    events = list(queryset)
    if not events:
        return 0

    envelopes = []
    for event in events:
        account = event.account
        envelopes.append(
            _envelope(
                {
                    "_epoch": event.occurred_at.timestamp(),
                    "record_type": "credential_lifecycle_event",
                    "event_kind": event.kind,
                    "outcome": event.outcome,
                    "actor": event.actor,
                    "source_address": event.source_address,
                    "ticket_reference": event.ticket_reference,
                    "pam_platform": account.system.name,
                    "pam_vendor": account.system.vendor,
                    "account_name": account.username,
                    "account_kind": account.kind,
                    "account_container": account.container,
                    "target_address": account.target_address,
                    "owner_identity": account.owner_identity,
                    "business_application": account.business_application,
                    "credential_age_days": account.credential_age_days,
                    "detail": event.detail,
                },
                source="pam:lifecycle",
            )
        )

    if not _ship(session, url, envelopes):
        return 0
    stamp = timezone.now()
    LifecycleEvent.objects.filter(pk__in=[event.pk for event in events]).update(exported_at=stamp)
    return len(events)


def export_findings() -> int:
    session, url = _session()
    if not session:
        return 0
    queryset = (
        Finding.objects.filter(exported_at__isnull=True)
        .select_related("account", "system")
        .order_by("opened_at")[:BATCH_SIZE]
    )
    findings = list(queryset)
    if not findings:
        return 0

    envelopes = []
    for finding in findings:
        account = finding.account
        envelopes.append(
            _envelope(
                {
                    "_epoch": finding.last_seen_at.timestamp(),
                    "record_type": "credential_governance_finding",
                    "rule_id": finding.rule_id,
                    "title": finding.title,
                    "category": finding.category,
                    "severity": finding.severity,
                    "state": finding.state,
                    "opened_at": finding.opened_at.isoformat(),
                    "age_days": finding.age_days,
                    "pam_platform": finding.system.name,
                    "pam_vendor": finding.system.vendor,
                    "account_name": account.username if account else "",
                    "account_kind": account.kind if account else "",
                    "target_address": account.target_address if account else "",
                    "owner_identity": account.owner_identity if account else "",
                    "evidence": finding.evidence,
                },
                source="pam:finding",
            )
        )

    if not _ship(session, url, envelopes):
        return 0
    stamp = timezone.now()
    Finding.objects.filter(pk__in=[finding.pk for finding in findings]).update(exported_at=stamp)
    return len(findings)
