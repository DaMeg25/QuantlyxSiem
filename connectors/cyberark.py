"""
CyberArk Privileged Access Manager (Password Vault Web Access REST interface).

Endpoint shapes below match the 12.x/13.x generation. Field names have moved
between versions -- confirm against your own environment's swagger before you
trust the mapping, and adjust FIELD_MAP rather than the parsing logic.

The service account used here needs, at minimum:
  * "List Accounts" on every safe in scope
  * "View Audit" for the activity feed
It must NOT hold "Retrieve Accounts". Grant only list and audit rights; the
collector has no code path that uses retrieval, and the vault-side permission
is the second half of that control.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Iterator

from .base import (
    Capability,
    ACCOUNT_KIND_UNKNOWN,
    STATUS_ACTIVE,
    STATUS_DISABLED,
    STATUS_UNKNOWN,
    ConnectorError,
    NormalizedAccount,
    NormalizedActivity,
    NormalizedUsage,
    PamConnector,
)

from .registry import register_connector

log = logging.getLogger(__name__)


@register_connector
class CyberArkConnector(PamConnector):
    vendor = "cyberark"
    display_name = "CyberArk Privileged Access Manager"
    required_credentials = ("username", "password")
    capabilities = frozenset({
        Capability.ACCOUNTS,
        Capability.ACTIVITY,
        Capability.ROTATION_INTERVAL,
        Capability.VERIFICATION,
        Capability.USAGE_TIMESTAMPS,
        Capability.OWNERSHIP,
        Capability.TICKET_REFERENCE,
        Capability.SESSION_TARGETS,
        Capability.APPLICATION_IDENTITY,
    })
    documentation = (
        "Password Vault Web Access interface. Grant List Accounts and View Audit; "
        "withhold Retrieve Accounts."
    )

    #: Activity verbs that indicate the vault changed the credential.
    ROTATION_ACTIONS = frozenset(
        {"CPM Change Password", "Change password", "CPM Verify Password", "CPM Reconcile Password"}
    )
    FAILURE_MARKERS = ("failed", "failure", "error")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._token: str | None = None
        self.auth_method = self.options.get("auth_method", "Cyberark")  # or LDAP, RADIUS, Windows

    # -- authentication --------------------------------------------------

    def authenticate(self) -> None:
        payload = {
            "username": self._credentials["username"],
            "password": self._credentials["password"],
            "concurrentSession": True,
        }
        token = self._post(
            f"/PasswordVault/API/auth/{self.auth_method}/Logon",
            json=payload,
        )
        if isinstance(token, str):
            self._token = token.strip('"')
        elif isinstance(token, dict):
            self._token = token.get("CyberArkLogonResult") or token.get("token")
        if not self._token:
            raise ConnectorError("CyberArk logon returned no session token")
        self.session.headers["Authorization"] = self._token

    def close(self) -> None:
        if self._token:
            try:
                self._post("/PasswordVault/API/auth/Logoff")
            except Exception:
                log.warning("CyberArk logoff failed; session will expire on its own")
            self._token = None
        super().close()

    # -- inventory -------------------------------------------------------

    def iter_accounts(self) -> Iterator[NormalizedAccount]:
        offset = 0
        seen = 0
        while True:
            page = self._get(
                "/PasswordVault/API/Accounts",
                params={"offset": offset, "limit": self.page_size},
            )
            items = page.get("value") or []
            if not items:
                break
            for item in items:
                yield self._to_account(item)
            seen += len(items)
            total = page.get("count")
            offset += len(items)
            if total is not None and seen >= int(total):
                break
            if len(items) < self.page_size:
                break

    def _to_account(self, item: dict[str, Any]) -> NormalizedAccount:
        secret_management = item.get("secretManagement") or {}
        remote_machines = item.get("remoteMachinesAccess") or {}
        properties = item.get("platformAccountProperties") or {}

        username = item.get("userName") or item.get("name") or ""
        container = item.get("safeName") or ""
        platform = item.get("platformId") or ""

        last_rotation = self.epoch_to_datetime(secret_management.get("lastModifiedTime"))
        last_verification = self.epoch_to_datetime(secret_management.get("lastVerifiedTime"))
        auto_managed = secret_management.get("automaticManagementEnabled")
        status_text = str(secret_management.get("status") or "").lower()

        interval = self._interval_days(properties)
        next_due = None
        if last_rotation and interval:
            next_due = last_rotation.fromtimestamp(
                last_rotation.timestamp() + interval * 86400, tz=last_rotation.tzinfo
            )

        return NormalizedAccount(
            external_id=str(item.get("id")),
            username=username,
            container=container,
            target_address=item.get("address") or remote_machines.get("remoteMachines") or "",
            platform=platform,
            kind=self.classify_kind(
                username=username,
                platform=platform,
                container=container,
                hints={"is_application": platform.lower().startswith("application")},
            )
            or ACCOUNT_KIND_UNKNOWN,
            status=self._status(item, status_text),
            owner_identity=properties.get("Owner") or properties.get("OwnerEmail") or "",
            owner_team=properties.get("BusinessOwnerGroup") or properties.get("Department") or "",
            business_application=properties.get("ApplicationName") or properties.get("CMDBID") or "",
            onboarded_at=self.epoch_to_datetime(item.get("createdTime")),
            last_rotation_at=last_rotation,
            next_rotation_due=next_due,
            rotation_interval_days=interval,
            auto_rotation_enabled=bool(auto_managed) if auto_managed is not None else None,
            last_verification_at=last_verification,
            verification_ok=None if not status_text else "success" in status_text,
            last_rotation_failed=any(marker in status_text for marker in self.FAILURE_MARKERS),
            rotation_failure_reason=str(secret_management.get("lastReconciledTime") and "" or secret_management.get("status") or ""),
            last_used_at=self.epoch_to_datetime(item.get("lastUsedTime")),
            exclusive_checkout=properties.get("ExclusiveUse") in (True, "true", "Yes"),
            raw=item,
        )

    @staticmethod
    def _status(item: dict[str, Any], status_text: str) -> str:
        if item.get("secretManagement", {}).get("manualManagementReason"):
            return STATUS_ACTIVE
        if "deleted" in status_text:
            return STATUS_DISABLED
        if item.get("categoryModificationTime") is None and not status_text:
            return STATUS_UNKNOWN
        return STATUS_ACTIVE

    def _interval_days(self, properties: dict[str, Any]) -> int | None:
        for key in ("ChangePasswordEveryXDays", "PasswordChangePeriod", "ResetOveridesTimeFrame"):
            value = properties.get(key)
            if value:
                try:
                    return int(value)
                except (TypeError, ValueError):
                    continue
        default = self.options.get("default_rotation_interval_days")
        return int(default) if default else None

    # -- activity --------------------------------------------------------

    def iter_activity(self, since: datetime) -> Iterator[NormalizedActivity]:
        """
        CyberArk exposes activity per account rather than as a global feed.
        Walking every account is expensive on large vaults; restrict it with
        options["activity_containers"] to the safes that matter for detections.
        """
        wanted = set(self.options.get("activity_containers", []))
        for account in self.iter_accounts():
            if wanted and account.container not in wanted:
                continue
            try:
                payload = self._get(f"/PasswordVault/API/Accounts/{account.external_id}/Activities")
            except ConnectorError as exc:
                log.warning("Activity fetch failed for %s: %s", account.external_id, exc)
                continue
            for entry in payload.get("value") or []:
                occurred = self.epoch_to_datetime(entry.get("Date"))
                if not occurred or occurred < since:
                    continue
                action = entry.get("Action") or ""
                yield NormalizedActivity(
                    external_id=f"{account.external_id}:{entry.get('Date')}:{action}",
                    account_external_id=account.external_id,
                    action=action,
                    occurred_at=occurred,
                    actor=entry.get("User") or "",
                    source_address=entry.get("ClientID") or "",
                    outcome="failure"
                    if any(m in action.lower() for m in self.FAILURE_MARKERS)
                    else "success",
                    reason=entry.get("Reason") or "",
                    ticket_reference=entry.get("TicketID") or "",
                    raw=entry,
                )


    # -- brokered sessions ------------------------------------------------

    def iter_usage(self, since: datetime) -> Iterator[NormalizedUsage]:
        """
        Sessions the Privileged Session Manager proxied.

        This is the only part of the usage picture a vault can state as fact:
        it brokered the connection, so it knows the target, the duration, and
        for command-level policies the commands themselves. Everything reached
        by a direct connection is invisible here and has to come from the
        target's own telemetry.
        """
        offset = 0
        while True:
            try:
                page = self._get(
                    "/PasswordVault/API/Recordings",
                    params={
                        "offset": offset,
                        "limit": self.page_size,
                        "search": "",
                        "fromTime": int(since.timestamp()),
                    },
                )
            except ConnectorError as exc:
                log.warning("Session recording feed unavailable: %s", exc)
                return
            items = page.get("Recordings") or page.get("value") or []
            if not items:
                return
            for item in items:
                started = self.epoch_to_datetime(item.get("StartTime") or item.get("start"))
                if not started or started < since:
                    continue
                duration = item.get("Duration") or 0
                try:
                    ended = self.epoch_to_datetime(started.timestamp() + int(duration))
                except (TypeError, ValueError):
                    ended = None
                target = (
                    item.get("RemoteMachine")
                    or item.get("TargetAddress")
                    or item.get("Client")
                    or ""
                )
                if not target:
                    continue
                yield NormalizedUsage(
                    external_id=str(item.get("SessionID") or item.get("id")),
                    account_external_id=str(item.get("AccountID") or item.get("accountId") or ""),
                    asset_identifier=target,
                    occurred_at=started,
                    ended_at=ended,
                    actor=item.get("User") or "",
                    source_address=item.get("FromIP") or "",
                    outcome="failure" if str(item.get("RiskScore", "")).lower() == "failed" else "success",
                    mechanism="brokered_session",
                    session_reference=str(item.get("SessionID") or ""),
                    command_count=item.get("CommandsCount"),
                    asset_hint=item.get("Protocol") or "",
                    raw=item,
                )
            offset += len(items)
            if len(items) < self.page_size:
                return
