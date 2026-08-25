"""
A connector you configure instead of writing.

Most Privileged Access Management platforms expose the same three things over a
web interface: a way to get a token, a paged list of accounts, and an audit
feed. When a new tool follows that shape, describe it as a mapping document in
`PamSystem.options["spec"]` and register it under a vendor key -- no Python, no
deployment.

Reach for a purpose-built subclass instead when the platform needs behaviour
this cannot express: per-account detail fetches, non-standard pagination,
request signing, or a second call to resolve ownership.

Worked example, a fictional platform:

    {
      "spec": {
        "auth": {
          "style": "token_post",
          "path": "/api/v2/session",
          "body": {"user": "{username}", "secret": "{password}"},
          "token_path": "data.sessionToken",
          "header": "Authorization",
          "header_format": "Bearer {token}"
        },
        "accounts": {
          "path": "/api/v2/accounts",
          "items_path": "data.items",
          "pagination": {
            "style": "offset",
            "limit_parameter": "limit",
            "offset_parameter": "offset",
            "total_path": "data.total"
          },
          "field_map": {
            "external_id": "accountId",
            "username": "loginName",
            "container": "vaultName",
            "target_address": "host.fqdn",
            "owner_identity": "owner.email",
            "last_rotation_at": {"path": "rotation.lastChanged", "transform": "epoch_ms"},
            "rotation_interval_days": {"path": "rotation.everyDays", "transform": "int"},
            "auto_rotation_enabled": {"path": "rotation.managed", "transform": "bool"},
            "status": {"path": "state", "map": {"ENABLED": "active", "LOCKED": "disabled"}},
            "verification_ok": {"path": "lastCheck.result", "equals": "OK"}
          }
        },
        "activity": {
          "path": "/api/v2/audit",
          "items_path": "data.events",
          "since_parameter": "from",
          "since_format": "iso",
          "field_map": {
            "external_id": "eventId",
            "account_external_id": "accountId",
            "action": "eventType",
            "occurred_at": {"path": "timestamp", "transform": "iso_datetime"},
            "actor": "principal",
            "source_address": "sourceIp",
            "ticket_reference": "changeTicket"
          }
        },
        "capabilities": ["accounts", "activity", "rotation_interval", "ownership"]
      }
    }

The blocked-path guard and payload scrubbing apply here exactly as they do to a
hand-written connector. A specification that points at a credential-retrieval
path fails at request time.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator, Mapping

from .base import (
    Capability,
    ConnectorError,
    NormalizedAccount,
    NormalizedActivity,
    PamConnector,
)

from .registry import register_connector

log = logging.getLogger(__name__)

ACCOUNT_FIELDS = set(NormalizedAccount.__annotations__) - {"raw"}
ACTIVITY_FIELDS = set(NormalizedActivity.__annotations__) - {"raw"}


class SpecificationError(ConnectorError):
    """The mapping document is malformed. Raised at construction, not mid-collection."""


def dig(payload: Any, path: str) -> Any:
    """Read a dotted path. Supports list indexes: "hosts.0.name"."""
    current = payload
    if not path:
        return None
    for part in path.split("."):
        if current is None:
            return None
        if isinstance(current, Mapping):
            current = current.get(part)
        elif isinstance(current, (list, tuple)):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return current


@register_connector
class GenericRestConnector(PamConnector):
    vendor = "generic"
    display_name = "Generic web interface (specification driven)"
    documentation = "Configured through options['spec']. See connectors/generic.py."

    TRANSFORMS = ("iso_datetime", "epoch", "epoch_ms", "int", "float", "bool", "not", "string", "seconds_to_days")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.spec: dict[str, Any] = dict(self.options.get("spec") or {})
        if not self.spec:
            raise SpecificationError(
                "This connector needs options['spec']. Configure the platform's "
                "authentication, account list, and field mapping there."
            )
        self._validate_spec()

    # -- specification handling -----------------------------------------

    def _validate_spec(self) -> None:
        accounts = self.spec.get("accounts")
        if not isinstance(accounts, Mapping) or not accounts.get("path"):
            raise SpecificationError("spec['accounts']['path'] is required")
        field_map = accounts.get("field_map") or {}
        for target in field_map:
            if target not in ACCOUNT_FIELDS:
                raise SpecificationError(
                    f"spec maps to unknown account field '{target}'. "
                    f"Valid fields: {sorted(ACCOUNT_FIELDS)}"
                )
        for required in ("external_id", "username"):
            if required not in field_map:
                raise SpecificationError(f"spec['accounts']['field_map'] must map '{required}'")
        activity = self.spec.get("activity") or {}
        for target in (activity.get("field_map") or {}):
            if target not in ACTIVITY_FIELDS:
                raise SpecificationError(f"spec maps to unknown activity field '{target}'")

    def declared_capabilities(self) -> frozenset[str]:
        declared = set(self.spec.get("capabilities") or [Capability.ACCOUNTS])
        unknown = declared - set(Capability.ALL)
        if unknown:
            raise SpecificationError(f"spec declares unknown capabilities: {sorted(unknown)}")
        declared.add(Capability.ACCOUNTS)
        removed = set(self.options.get("disabled_capabilities", []))
        return frozenset(declared - removed)

    # -- authentication --------------------------------------------------

    def authenticate(self) -> None:
        auth = self.spec.get("auth") or {"style": "none"}
        style = auth.get("style", "none")

        if style == "none":
            return

        if style == "static_header":
            header = auth.get("header", "Authorization")
            self.session.headers[header] = self._interpolate(auth.get("format", "{token}"))
            return

        if style == "basic":
            self.session.auth = (
                self._credentials.get("username", ""),
                self._credentials.get("password", ""),
            )
            return

        if style in ("token_post", "oauth2_password"):
            path = auth.get("path")
            if not path:
                raise SpecificationError("spec['auth']['path'] is required for this style")
            body = {key: self._interpolate(value) for key, value in (auth.get("body") or {}).items()}
            if style == "oauth2_password":
                body.setdefault("grant_type", "password")
                payload = self._post(path, data=body)
            else:
                payload = self._post(path, json=body)
            token = dig(payload, auth.get("token_path", "access_token"))
            if isinstance(payload, str) and not token:
                token = payload.strip('"')
            if not token:
                raise ConnectorError(
                    f"Authentication returned no value at '{auth.get('token_path')}'"
                )
            header = auth.get("header", "Authorization")
            self.session.headers[header] = auth.get("header_format", "Bearer {token}").format(token=token)
            return

        raise SpecificationError(f"Unsupported authentication style '{style}'")

    def _interpolate(self, template: Any) -> Any:
        if not isinstance(template, str):
            return template
        try:
            return template.format(**self._credentials)
        except KeyError as exc:
            raise SpecificationError(
                f"spec references credential key {exc} that the credential reference does not contain"
            ) from exc

    # -- paging ----------------------------------------------------------

    def _iter_pages(self, block: Mapping[str, Any], extra_parameters: dict[str, Any] | None = None) -> Iterator[Any]:
        pagination = block.get("pagination") or {"style": "none"}
        style = pagination.get("style", "none")
        items_path = block.get("items_path", "")
        parameters = dict(block.get("parameters") or {})
        parameters.update(extra_parameters or {})
        guard = int(pagination.get("maximum_pages", 500))

        if style == "none":
            payload = self._get(block["path"], params=parameters)
            yield from self._items(payload, items_path)
            return

        offset = int(pagination.get("start", 0))
        cursor = None
        for _ in range(guard):
            page_parameters = dict(parameters)
            if style == "offset":
                page_parameters[pagination.get("limit_parameter", "limit")] = self.page_size
                page_parameters[pagination.get("offset_parameter", "offset")] = offset
            elif style == "page":
                page_parameters[pagination.get("size_parameter", "per_page")] = self.page_size
                page_parameters[pagination.get("page_parameter", "page")] = offset
            elif style == "cursor":
                page_parameters[pagination.get("limit_parameter", "limit")] = self.page_size
                if cursor:
                    page_parameters[pagination.get("cursor_parameter", "cursor")] = cursor
            else:
                raise SpecificationError(f"Unsupported pagination style '{style}'")

            payload = self._get(block["path"], params=page_parameters)
            items = list(self._items(payload, items_path))
            yield from items

            if style == "cursor":
                cursor = dig(payload, pagination.get("next_cursor_path", "next"))
                if not cursor:
                    return
                continue

            if not items or len(items) < self.page_size:
                return
            offset += len(items) if style == "offset" else 1

            total_path = pagination.get("total_path")
            if total_path:
                total = dig(payload, total_path)
                if isinstance(total, int) and style == "offset" and offset >= total:
                    return
        log.warning("Pagination guard reached for %s; results may be truncated", block["path"])

    @staticmethod
    def _items(payload: Any, items_path: str) -> Iterator[Any]:
        block = dig(payload, items_path) if items_path else payload
        if block is None:
            return iter(())
        if isinstance(block, Mapping):
            block = [block]
        return iter(block)

    # -- mapping ---------------------------------------------------------

    def _map(self, item: Mapping[str, Any], field_map: Mapping[str, Any]) -> dict[str, Any]:
        mapped: dict[str, Any] = {}
        for target, rule in field_map.items():
            if isinstance(rule, str):
                value = dig(item, rule)
            elif isinstance(rule, Mapping):
                value = dig(item, rule.get("path", ""))
                if "equals" in rule:
                    value = None if value is None else value == rule["equals"]
                if "map" in rule and value is not None:
                    value = rule["map"].get(str(value), rule.get("default"))
                if value is None and "default" in rule:
                    value = rule["default"]
                transform = rule.get("transform")
                if transform:
                    value = self._transform(value, transform)
            else:
                raise SpecificationError(f"Field rule for '{target}' must be a string or an object")
            if value is not None:
                mapped[target] = value
        return mapped

    def _transform(self, value: Any, name: str) -> Any:
        if value is None:
            return None
        if name == "iso_datetime":
            return self.iso_to_datetime(value)
        if name in ("epoch", "epoch_ms"):
            return self.epoch_to_datetime(value)
        if name == "int":
            try:
                return int(value)
            except (TypeError, ValueError):
                return None
        if name == "float":
            try:
                return float(value)
            except (TypeError, ValueError):
                return None
        if name == "bool":
            return str(value).strip().lower() in ("1", "true", "yes", "on", "enabled")
        if name == "not":
            return not (str(value).strip().lower() in ("1", "true", "yes", "on", "enabled"))
        if name == "string":
            return str(value)
        if name == "seconds_to_days":
            try:
                return max(1, int(int(value) / 86400))
            except (TypeError, ValueError):
                return None
        raise SpecificationError(f"Unknown transform '{name}'. Available: {self.TRANSFORMS}")

    # -- contract --------------------------------------------------------

    def iter_accounts(self) -> Iterator[NormalizedAccount]:
        block = self.spec["accounts"]
        field_map = block["field_map"]
        for item in self._iter_pages(block):
            if not isinstance(item, Mapping):
                continue
            mapped = self._map(item, field_map)
            mapped["external_id"] = str(mapped.get("external_id", ""))
            if not mapped["external_id"]:
                continue
            account = NormalizedAccount(raw=dict(item), **mapped)
            if "kind" not in field_map:
                account.kind = self.classify_kind(
                    username=account.username,
                    platform=account.platform,
                    container=account.container,
                )
            if account.next_rotation_due is None and account.last_rotation_at and account.rotation_interval_days:
                account.next_rotation_due = account.last_rotation_at + timedelta(
                    days=account.rotation_interval_days
                )
            yield account

    def iter_activity(self, since: datetime) -> Iterator[NormalizedActivity]:
        block = self.spec.get("activity")
        if not block or Capability.ACTIVITY not in self.declared_capabilities():
            return iter(())
        parameter = block.get("since_parameter")
        extra: dict[str, Any] = {}
        if parameter:
            style = block.get("since_format", "iso")
            if style == "iso":
                extra[parameter] = since.astimezone(timezone.utc).isoformat()
            elif style == "epoch":
                extra[parameter] = int(since.timestamp())
            elif style == "epoch_ms":
                extra[parameter] = int(since.timestamp() * 1000)
            else:
                raise SpecificationError(f"Unknown since_format '{style}'")

        field_map = block.get("field_map", {})
        for item in self._iter_pages(block, extra):
            if not isinstance(item, Mapping):
                continue
            mapped = self._map(item, field_map)
            occurred = mapped.get("occurred_at")
            if not isinstance(occurred, datetime) or occurred < since:
                continue
            mapped["external_id"] = str(mapped.get("external_id", ""))
            mapped["account_external_id"] = str(mapped.get("account_external_id", ""))
            if not mapped["account_external_id"]:
                continue
            yield NormalizedActivity(raw=dict(item), **mapped)
