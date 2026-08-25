"""
BeyondTrust Password Safe.

Metadata surfaces:
  * /Auth/SignAppin, /Auth/Signout
  * /ManagedAccounts        -- inventory and change-policy state
  * /ManagedSystems         -- target context for each account
  * /UserAudits             -- optional activity feed

Never /Credentials or /Requests/{id}/Checkout.

Authentication uses the API registration key plus a run-as user, sent as
"Authorization: PS-Auth key=<key>; runas=<user>; pwd=[<password>];".
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
    NormalizedUsage,
    PamConnector,
)

from .registry import register_connector

log = logging.getLogger(__name__)


@register_connector
class BeyondTrustConnector(PamConnector):
    vendor = "beyondtrust"
    display_name = "BeyondTrust Password Safe"
    required_credentials = ("api_key", "run_as_user")
    capabilities = frozenset({
        Capability.ACCOUNTS,
        Capability.ACTIVITY,
        Capability.ROTATION_INTERVAL,
        Capability.VERIFICATION,
        Capability.OWNERSHIP,
        Capability.ENTITLEMENTS,
        Capability.SESSION_TARGETS,
    })

    def authenticate(self) -> None:
        key = self._credentials["api_key"]
        run_as = self._credentials["run_as_user"]
        run_as_password = self._credentials.get("run_as_password", "")
        header = f"PS-Auth key={key}; runas={run_as};"
        if run_as_password:
            header += f" pwd=[{run_as_password}];"
        self.session.headers["Authorization"] = header
        result = self._post("/Auth/SignAppin")
        if not result:
            raise ConnectorError("Password Safe sign-in returned an empty body")

    def close(self) -> None:
        try:
            self._post("/Auth/Signout")
        except Exception:
            log.debug("Password Safe sign-out failed", exc_info=True)
        super().close()

    def iter_accounts(self) -> Iterator[NormalizedAccount]:
        systems = {}
        try:
            for system in self._get("/ManagedSystems") or []:
                systems[system.get("ManagedSystemID")] = system
        except ConnectorError as exc:
            log.warning("Managed system list unavailable: %s", exc)

        accounts = self._get("/ManagedAccounts") or []
        for item in accounts:
            system = systems.get(item.get("ManagedSystemID"), {})
            yield self._to_account(item, system)

    def _to_account(self, item: dict[str, Any], system: dict[str, Any]) -> NormalizedAccount:
        username = item.get("AccountName") or ""
        platform = system.get("PlatformID") and str(system.get("PlatformID")) or item.get("PlatformID", "")
        container = item.get("DomainName") or system.get("SystemName") or ""

        interval = item.get("ChangeFrequencyDays")
        try:
            interval = int(interval) if interval else None
        except (TypeError, ValueError):
            interval = None

        return NormalizedAccount(
            external_id=str(item.get("ManagedAccountID")),
            username=username,
            container=container,
            target_address=system.get("SystemName") or item.get("SystemName") or "",
            platform=str(platform),
            kind=self.classify_kind(username=username, platform=str(platform), container=container),
            status=STATUS_DISABLED if item.get("IsDisabled") else STATUS_ACTIVE,
            owner_identity=item.get("OwnerType") == "User" and str(item.get("OwnerID") or "") or "",
            owner_team=item.get("OwnerType") == "Group" and str(item.get("OwnerID") or "") or "",
            business_application=item.get("Description") or "",
            last_rotation_at=self.iso_to_datetime(item.get("LastChangeDate")),
            next_rotation_due=self.iso_to_datetime(item.get("NextChangeDate")),
            rotation_interval_days=interval,
            auto_rotation_enabled=bool(item.get("AutoManagementFlag")),
            verification_ok=None if item.get("LastChangeResult") is None else str(item.get("LastChangeResult")).lower() == "success",
            last_rotation_failed=str(item.get("LastChangeResult", "")).lower() not in ("success", ""),
            rotation_failure_reason=str(item.get("LastChangeResult") or ""),
            exclusive_checkout=bool(item.get("MaxReleaseDuration")) and int(item.get("MaxConcurrentRequests") or 0) == 1,
            entitled_identity_count=item.get("MaxConcurrentRequests"),
            raw={**item, "_system": system},
        )

    def iter_activity(self, since: datetime) -> Iterator[NormalizedActivity]:
        try:
            audits = self._get("/UserAudits", params={"limit": self.page_size}) or []
        except ConnectorError as exc:
            log.warning("User audit feed unavailable: %s", exc)
            return iter(())
        for row in audits:
            occurred = self.iso_to_datetime(row.get("CreateDate"))
            if not occurred or occurred < since:
                continue
            yield NormalizedActivity(
                external_id=str(row.get("UserAuditID") or row.get("ID")),
                account_external_id=str(row.get("ManagedAccountID") or ""),
                action=row.get("Action") or row.get("Section") or "",
                occurred_at=occurred,
                actor=row.get("UserName") or "",
                source_address=row.get("IPAddress") or "",
                outcome="success",
                raw=row,
            )


    # -- brokered sessions ------------------------------------------------

    def iter_usage(self, since: datetime) -> Iterator[NormalizedUsage]:
        try:
            sessions = self._get("/Sessions", params={"status": 2}) or []
        except ConnectorError as exc:
            log.warning("Session feed unavailable: %s", exc)
            return
        for item in sessions:
            started = self.iso_to_datetime(item.get("StartTime"))
            if not started or started < since:
                continue
            target = item.get("AssetName") or item.get("NodeName") or ""
            if not target:
                continue
            yield NormalizedUsage(
                external_id=str(item.get("SessionID") or item.get("ID")),
                account_external_id=str(item.get("ManagedAccountID") or ""),
                asset_identifier=target,
                occurred_at=started,
                ended_at=self.iso_to_datetime(item.get("EndTime")),
                actor=item.get("UserID") and str(item.get("UserID")) or "",
                source_address=item.get("NodeID") or "",
                mechanism="brokered_session",
                session_reference=str(item.get("SessionID") or ""),
                asset_hint=item.get("Protocol") or "",
                raw=item,
            )
