"""
Delinea Secret Server (formerly Thycotic).

Uses the metadata surfaces only:
  * /api/v1/secrets                 -- inventory with lifecycle summary fields
  * /api/v1/secrets/{id}            -- per-secret detail with heartbeat state
  * /api/v1/reports/execute         -- optional, for audit extraction
Never /api/v1/secrets/{id}/fields/password.

Grant the collector role "View Secret" and "View Audit" without "View Launcher
Password" or "Retrieve Secret".
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Iterator

from .base import (
    Capability,
    STATUS_ACTIVE,
    STATUS_DISABLED,
    ConnectorError,
    NormalizedAccount,
    NormalizedActivity,
    PamConnector,
)

from .registry import register_connector

log = logging.getLogger(__name__)


@register_connector
class DelineaConnector(PamConnector):
    vendor = "delinea"
    display_name = "Delinea Secret Server"
    required_credentials = ("username", "password")
    capabilities = frozenset({
        Capability.ACCOUNTS,
        Capability.ROTATION_INTERVAL,
        Capability.VERIFICATION,
        Capability.USAGE_TIMESTAMPS,
        Capability.OWNERSHIP,
    })
    documentation = (
        "Activity requires an audit report identifier in options['audit_report_id']; "
        "without it the activity capability stays off."
    )

    HEARTBEAT_OK = {"success", "ok", "pending"}

    def declared_capabilities(self):
        capabilities = set(super().declared_capabilities())
        if self.options.get("audit_report_id"):
            capabilities.add(Capability.ACTIVITY)
        return frozenset(capabilities)

    def authenticate(self) -> None:
        data = {
            "username": self._credentials["username"],
            "password": self._credentials["password"],
            "grant_type": "password",
        }
        payload = self._post("/oauth2/token", data=data)
        token = payload.get("access_token")
        if not token:
            raise ConnectorError("Secret Server token endpoint returned no access_token")
        self.session.headers["Authorization"] = f"Bearer {token}"

    def iter_accounts(self) -> Iterator[NormalizedAccount]:
        skip = 0
        while True:
            page = self._get(
                "/api/v1/secrets",
                params={
                    "skip": skip,
                    "take": self.page_size,
                    "includeInactive": str(self.options.get("include_inactive", True)).lower(),
                    "sortBy[0].direction": "asc",
                    "sortBy[0].name": "id",
                },
            )
            records = page.get("records") or []
            if not records:
                break
            for summary in records:
                detail = self._detail(summary.get("id"))
                yield self._to_account(summary, detail)
            skip += len(records)
            if not page.get("hasNext"):
                break

    def _detail(self, secret_id: Any) -> dict[str, Any]:
        if not secret_id or not self.options.get("fetch_detail", True):
            return {}
        try:
            # summary=true keeps the response free of field values entirely.
            return self._get(f"/api/v1/secrets/{secret_id}/summary")
        except ConnectorError as exc:
            log.warning("Secret %s summary unavailable: %s", secret_id, exc)
            return {}

    def _to_account(self, summary: dict[str, Any], detail: dict[str, Any]) -> NormalizedAccount:
        merged: dict[str, Any] = {**summary, **detail}
        username = merged.get("secretName") or merged.get("name") or ""
        container = merged.get("folderPath") or str(merged.get("folderId") or "")
        template = merged.get("secretTemplateName") or ""

        heartbeat = str(merged.get("lastHeartBeatStatus") or "").lower()
        last_rotation = self.iso_to_datetime(
            merged.get("lastPasswordChangeAttempt") or merged.get("lastPasswordChange")
        )
        interval = merged.get("passwordChangeInterval") or merged.get("autoChangeIntervalDays")
        try:
            interval = int(interval) if interval else None
        except (TypeError, ValueError):
            interval = None
        if interval is None and self.options.get("default_rotation_interval_days"):
            interval = int(self.options["default_rotation_interval_days"])

        auto_change = merged.get("autoChangeEnabled")
        active = merged.get("active")

        return NormalizedAccount(
            external_id=str(merged.get("id")),
            username=username,
            container=container,
            target_address=merged.get("machine") or merged.get("computer") or "",
            platform=template,
            kind=self.classify_kind(username=username, platform=template, container=container),
            status=STATUS_ACTIVE if active in (True, None) else STATUS_DISABLED,
            owner_identity=merged.get("secretOwner") or "",
            owner_team=merged.get("folderPath", "").split("\\")[1] if "\\" in str(merged.get("folderPath", "")) else "",
            business_application=merged.get("secretPolicyName") or "",
            onboarded_at=self.iso_to_datetime(merged.get("createdDate")),
            last_rotation_at=last_rotation,
            rotation_interval_days=interval,
            auto_rotation_enabled=bool(auto_change) if auto_change is not None else None,
            last_verification_at=self.iso_to_datetime(merged.get("lastHeartBeatCheck")),
            verification_ok=heartbeat in self.HEARTBEAT_OK if heartbeat else None,
            last_rotation_failed=str(merged.get("lastPasswordChangeStatus", "")).lower().startswith("fail"),
            rotation_failure_reason=merged.get("lastPasswordChangeStatus") or "",
            last_used_at=self.iso_to_datetime(merged.get("lastAccessed")),
            exclusive_checkout=bool(merged.get("checkOutEnabled")),
            raw=merged,
        )

    def iter_activity(self, since: datetime) -> Iterator[NormalizedActivity]:
        report_id = self.options.get("audit_report_id")
        if not report_id:
            return iter(())
        payload = self._post(
            "/api/v1/reports/execute",
            json={"id": int(report_id), "parameters": {"startDate": since.isoformat()}},
        )
        for row in payload.get("rows") or []:
            occurred = self.iso_to_datetime(row.get("dateRecorded"))
            if not occurred:
                continue
            yield NormalizedActivity(
                external_id=str(row.get("auditSecretId") or row.get("id")),
                account_external_id=str(row.get("secretId")),
                action=row.get("action") or "",
                occurred_at=occurred,
                actor=row.get("username") or "",
                source_address=row.get("ipAddress") or "",
                outcome="failure" if "fail" in str(row.get("action", "")).lower() else "success",
                reason=row.get("notes") or "",
                ticket_reference=row.get("ticketNumber") or "",
                raw=row,
            )
