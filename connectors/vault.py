"""
HashiCorp Vault, database and Active Directory static roles.

Static roles are the part of Vault that carries credential lifecycle state:
each role has a rotation_period and a last_vault_rotation. Dynamic secrets are
covered through lease metadata rather than role metadata.

Read surfaces:
  * /v1/auth/approle/login
  * /v1/{mount}/static-roles?list=true and /v1/{mount}/static-roles/{name}
  * /v1/sys/leases/lookup (optional, requires a privileged policy)

Never /v1/{mount}/static-creds/{name}, which returns the password itself. The
collector's blocked-path list refuses that request even if a future change
tries to make it.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

from .base import (
    Capability,
    ACCOUNT_KIND_SERVICE,
    STATUS_ACTIVE,
    ConnectorError,
    NormalizedAccount,
    PamConnector,
)

from .registry import register_connector

log = logging.getLogger(__name__)


@register_connector
class VaultConnector(PamConnector):
    vendor = "hashicorp_vault"
    display_name = "HashiCorp Vault (static roles)"
    capabilities = frozenset({Capability.ACCOUNTS, Capability.ROTATION_INTERVAL})
    documentation = (
        "Static roles only. Dynamic secrets have no durable identity to track, so "
        "they are out of scope for lifecycle reporting."
    )

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Each mount is a secrets engine path, for example "database" or "ad".
        self.mounts: list[str] = list(self.options.get("mounts", ["database"]))

    def authenticate(self) -> None:
        role_id = self._credentials.get("role_id")
        secret_id = self._credentials.get("secret_id")
        if role_id and secret_id:
            payload = self._post(
                "/v1/auth/approle/login",
                json={"role_id": role_id, "secret_id": secret_id},
            )
            token = (payload.get("auth") or {}).get("client_token")
            if not token:
                raise ConnectorError("AppRole login returned no client token")
        else:
            token = self._credentials["token"]
        self.session.headers["X-Vault-Token"] = token
        namespace = self.options.get("namespace")
        if namespace:
            self.session.headers["X-Vault-Namespace"] = namespace

    def iter_accounts(self) -> Iterator[NormalizedAccount]:
        for mount in self.mounts:
            for name in self._list_roles(mount):
                try:
                    detail = self._get(f"/v1/{mount}/static-roles/{name}")
                except ConnectorError as exc:
                    log.warning("Static role %s/%s unreadable: %s", mount, name, exc)
                    continue
                yield self._to_account(mount, name, detail.get("data") or {})

    def _list_roles(self, mount: str) -> list[str]:
        try:
            payload = self._get(f"/v1/{mount}/static-roles", params={"list": "true"})
        except ConnectorError as exc:
            log.warning("Cannot list static roles on mount %s: %s", mount, exc)
            return []
        return list((payload.get("data") or {}).get("keys") or [])

    def _to_account(self, mount: str, role: str, data: dict[str, Any]) -> NormalizedAccount:
        last_rotation = self.iso_to_datetime(data.get("last_vault_rotation"))
        period_seconds = data.get("rotation_period")
        interval_days = None
        next_due = None
        if period_seconds:
            try:
                interval_days = max(1, int(int(period_seconds) / 86400))
                if last_rotation:
                    next_due = last_rotation + timedelta(seconds=int(period_seconds))
            except (TypeError, ValueError):
                interval_days = None

        username = data.get("username") or role
        return NormalizedAccount(
            external_id=f"{mount}/{role}",
            username=username,
            container=mount,
            target_address=data.get("db_name") or data.get("dn") or "",
            platform=f"vault:{mount}",
            kind=self.classify_kind(username=username, platform=mount, container=mount)
            or ACCOUNT_KIND_SERVICE,
            status=STATUS_ACTIVE,
            owner_identity="",
            business_application=role,
            last_rotation_at=last_rotation,
            next_rotation_due=next_due,
            rotation_interval_days=interval_days,
            # A static role always rotates on schedule; rotation_period of 0
            # means the operator disabled it.
            auto_rotation_enabled=bool(period_seconds),
            raw={"mount": mount, "role": role, **data},
        )
