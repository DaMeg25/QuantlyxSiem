"""
Feeds this system pulls for itself, rather than waiting for a file.

The file parsers in ingest.py stay the right answer when the enterprise event
platform already has the data and can drop an export somewhere. These collectors
are for when it does not, or when you want the credential-utilisation picture
without adding a hop through another team's pipeline.

TACACS+ accounting is the reason this module exists. On a network estate it is
by far the richest evidence of credential use: it names the device, the account,
the privilege level obtained, and every command entered, per session. Nothing a
vault can produce comes close, because the vault only knows the credential was
handed out.

Three ways to get it, in descending order of fidelity:

  1. Identity Services Engine Data Connect. A read-only database view over the
     accounting records, present from Identity Services Engine 3.2. Complete,
     queryable, and it back-fills -- ask for a week and get a week.
  2. Syslog. Identity Services Engine forwards accounting messages to a
     collector; this reads the spool directory and tracks its position across
     rotations. Live, but only from the moment forwarding was switched on, and
     it inherits whatever the syslog transport dropped.
  3. A tac_plus daemon accounting log, for estates not running Identity Services
     Engine.

Every collector yields the same dictionary shape the parsers do, so correlation,
rules, and the dashboard are unchanged.
"""

from __future__ import annotations

import glob
import logging
import os
import re
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone as datetime_timezone
from pathlib import Path
from typing import Iterator, Mapping

from django.utils import timezone

from inventory.models import UsageObservation

from .ingest import TACACS_FIELD, _parse_timestamp

log = logging.getLogger(__name__)

_COLLECTORS: dict[str, type["TelemetryCollector"]] = {}


class CollectorError(RuntimeError):
    pass


def register_collector(cls: type["TelemetryCollector"]) -> type["TelemetryCollector"]:
    if not cls.key:
        raise ValueError(f"{cls.__name__} needs a collector key")
    _COLLECTORS[cls.key] = cls
    return cls


def collector_registry() -> Mapping[str, type["TelemetryCollector"]]:
    return dict(_COLLECTORS)


def collector_choices() -> list[tuple[str, str]]:
    return [("", "Delivered as files (parsed from the ingest reference)")] + sorted(
        (key, cls.display_name) for key, cls in _COLLECTORS.items()
    )


def build_collector(source) -> "TelemetryCollector":
    try:
        cls = _COLLECTORS[source.collector]
    except KeyError as exc:
        raise CollectorError(
            f"No collector registered for '{source.collector}'. Registered: {sorted(_COLLECTORS)}"
        ) from exc
    credentials = {}
    if source.credential_reference:
        from connectors.registry import resolve_credentials

        credentials = resolve_credentials(source.credential_reference)
    return cls(settings=source.settings or {}, credentials=credentials, cursor=source.cursor or {})


class TelemetryCollector(ABC):
    """
    Pull authentication or accounting records from a system that holds them.

    Collectors are read-only by contract. Nothing here writes to a network
    device, an identity platform, or a vault; a collector that needed write
    access would be the wrong tool for this job.
    """

    key: str = ""
    display_name: str = ""
    kind: str = ""
    required_settings: tuple[str, ...] = ()
    required_credentials: tuple[str, ...] = ()
    documentation: str = ""

    def __init__(self, *, settings: Mapping, credentials: Mapping, cursor: Mapping):
        self.settings = dict(settings)
        self._credentials = dict(credentials)
        self.cursor = dict(cursor)
        missing = [key for key in self.required_settings if not self.settings.get(key)]
        if missing:
            raise CollectorError(f"{self.key} needs settings {sorted(missing)}")
        missing = [key for key in self.required_credentials if not self._credentials.get(key)]
        if missing:
            raise CollectorError(
                f"{self.key} needs credential keys {sorted(missing)} behind its credential reference"
            )

    @abstractmethod
    def collect(self, since: datetime) -> Iterator[dict]: ...

    def next_cursor(self) -> dict:
        """Where the next pull should resume. Persisted on the source row."""
        return self.cursor


# --------------------------------------------------------------------------
# Identity Services Engine Data Connect
# --------------------------------------------------------------------------


@register_collector
class IseDataConnectCollector(TelemetryCollector):
    """
    Read TACACS+ accounting straight from Identity Services Engine.

    Data Connect exposes read-only database views over the monitoring data,
    including device administration accounting. It is the only one of the three
    routes that can back-fill: point it at a week ago and you get a week, which
    matters when you are trying to establish a utilisation baseline rather than
    start collecting one.

    Setup on the Identity Services Engine side: enable Data Connect, take the
    generated read-only user and the certificate, and confirm the view name
    against your own release before trusting the numbers -- view names have
    moved between releases and this defaults to the 3.2 naming.

    Requires the `oracledb` package, which is not in requirements.txt because
    most deployments do not need it. Install it only where this collector runs.
    """

    key = "ise_data_connect"
    display_name = "Identity Services Engine Data Connect (TACACS+ accounting)"
    kind = "network_aaa"
    required_settings = ("host",)
    required_credentials = ("username", "password")
    documentation = (
        "Read-only database view over device administration accounting. "
        "Confirm the view name against your Identity Services Engine release."
    )

    DEFAULT_VIEW = "TACACS_ACCOUNTING"
    DEFAULT_PORT = 2484
    DEFAULT_SERVICE = "cpm10"

    #: Column names as of the 3.2 view. Override per deployment in settings
    #: rather than editing this, so an upgrade is a configuration change.
    DEFAULT_COLUMNS = {
        "timestamp": "TIMESTAMP",
        "username": "USERNAME",
        "device": "NETWORK_DEVICE_NAME",
        "device_address": "NAS_IP_ADDRESS",
        "session": "ACCT_SESSION_ID",
        "command": "CMD_SET",
        "privilege": "PRIV_LVL",
        "source_address": "REMOTE_ADDRESS",
        "status": "AUTHEN_ACTION",
    }

    def _connection(self):
        try:
            import oracledb  # noqa: PLC0415 -- optional dependency by design
        except ImportError as exc:  # pragma: no cover
            raise CollectorError(
                "This collector needs the 'oracledb' package. Install it on the host that "
                "runs collection: pip install oracledb"
            ) from exc

        dsn = self.settings.get("dsn") or oracledb.makedsn(
            self.settings["host"],
            int(self.settings.get("port", self.DEFAULT_PORT)),
            service_name=self.settings.get("service_name", self.DEFAULT_SERVICE),
        )
        return oracledb.connect(
            user=self._credentials["username"],
            password=self._credentials["password"],
            dsn=dsn,
            ssl_server_dn_match=bool(self.settings.get("verify_server_name", True)),
            wallet_location=self.settings.get("wallet_location"),
        )

    def collect(self, since: datetime) -> Iterator[dict]:
        columns = {**self.DEFAULT_COLUMNS, **(self.settings.get("columns") or {})}
        view = self.settings.get("view", self.DEFAULT_VIEW)
        limit = int(self.settings.get("row_limit", 50000))

        start = since
        if self.cursor.get("last_timestamp"):
            recorded = _parse_timestamp(self.cursor["last_timestamp"])
            if recorded:
                start = max(start, recorded)

        selected = ", ".join(f"{column} AS {alias}" for alias, column in columns.items())
        statement = (
            f"SELECT {selected} FROM {view} "
            f"WHERE {columns['timestamp']} > :start "
            f"ORDER BY {columns['timestamp']} FETCH FIRST {limit} ROWS ONLY"
        )

        latest = start
        sessions: dict[str, dict] = {}
        with self._connection() as connection:
            cursor = connection.cursor()
            cursor.execute(statement, start=start.replace(tzinfo=None))
            names = [description[0].lower() for description in cursor.description]
            for row in cursor:
                record = dict(zip(names, row))
                occurred = record.get("timestamp")
                if isinstance(occurred, datetime) and timezone.is_naive(occurred):
                    occurred = occurred.replace(tzinfo=datetime_timezone.utc)
                device = record.get("device") or record.get("device_address")
                account = record.get("username")
                if not (occurred and device and account):
                    continue
                latest = max(latest, occurred)

                # One accounting row per command. Roll them into one session so
                # a twenty-command change is one login, not twenty.
                key = str(record.get("session") or f"{device}:{account}:{occurred:%Y%m%d%H%M}")
                entry = sessions.setdefault(
                    key,
                    {
                        "observed_account_name": str(account),
                        "asset_identifier": str(device),
                        "asset_address": str(record.get("device_address") or ""),
                        "asset_hint": "network device",
                        "occurred_at": occurred,
                        "mechanism": UsageObservation.Mechanism.NETWORK_AAA,
                        "source_address": str(record.get("source_address") or ""),
                        "privilege_level": str(record.get("privilege") or ""),
                        "outcome": "failure"
                        if "fail" in str(record.get("status", "")).lower()
                        else "success",
                        "session_reference": key,
                        "command_count": 0,
                        "detail": {"commands": []},
                    },
                )
                entry["occurred_at"] = min(entry["occurred_at"], occurred)
                entry["ended_at"] = occurred
                command = record.get("command")
                if command:
                    entry["command_count"] += 1
                    if len(entry["detail"]["commands"]) < 25:
                        entry["detail"]["commands"].append(str(command))

        self.cursor = {"last_timestamp": latest.isoformat()}
        yield from sessions.values()


# --------------------------------------------------------------------------
# Syslog spool
# --------------------------------------------------------------------------


@register_collector
class SyslogSpoolCollector(TelemetryCollector):
    """
    Read accounting messages a syslog collector has already written to disk.

    Tracks a file and byte offset per pull, and handles rotation by falling back
    to the start of a file whose size has shrunk. Works for Identity Services
    Engine device administration messages and anything else emitting key=value
    accounting lines.

    Note what this cannot do: it sees nothing from before forwarding was turned
    on, and nothing the syslog transport dropped. If you need a baseline of how
    heavily a credential has been used historically, use Data Connect.
    """

    key = "syslog_spool"
    display_name = "Syslog spool directory (TACACS+ or device administration)"
    kind = "network_aaa"
    required_settings = ("path_glob",)
    documentation = "Reads key=value accounting lines from rotating syslog files."

    def collect(self, since: datetime) -> Iterator[dict]:
        pattern = self.settings["path_glob"]
        offsets: dict[str, int] = dict(self.cursor.get("offsets") or {})
        max_bytes = int(self.settings.get("max_bytes_per_pull", 64 * 1024 * 1024))

        sessions: dict[str, dict] = {}
        consumed = 0
        for path in sorted(glob.glob(pattern)):
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            start = offsets.get(path, 0)
            if start > size:
                # The file was rotated or truncated underneath us.
                start = 0
            if start == size:
                continue

            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                handle.seek(start)
                for line in handle:
                    consumed += len(line)
                    record = self._parse_line(line, since)
                    if record:
                        key = record["session_reference"]
                        entry = sessions.setdefault(key, record)
                        if entry is not record:
                            entry["command_count"] = (entry.get("command_count") or 0) + (
                                record.get("command_count") or 0
                            )
                            entry["ended_at"] = max(
                                entry.get("ended_at") or entry["occurred_at"],
                                record["occurred_at"],
                            )
                            commands = record["detail"].get("commands") or []
                            if commands and len(entry["detail"]["commands"]) < 25:
                                entry["detail"]["commands"].extend(commands)
                    if consumed >= max_bytes:
                        break
                offsets[path] = handle.tell()
            if consumed >= max_bytes:
                log.info("Reached the per-pull byte limit; remaining records follow next run")
                break

        self.cursor = {"offsets": offsets}
        yield from sessions.values()

    @staticmethod
    def _parse_line(line: str, since: datetime) -> dict | None:
        fields = {key: value.strip('"') for key, value in TACACS_FIELD.findall(line)}
        if not fields:
            return None
        device = fields.get("NetworkDeviceName") or fields.get("NAS-IP-Address")
        account = fields.get("UserName") or fields.get("User-Name")
        occurred = _parse_timestamp(fields.get("Timestamp") or fields.get("time") or "")
        if not (device and account and occurred) or occurred < since:
            return None
        command = fields.get("CmdSet") or fields.get("Command") or fields.get("cmd")
        session = fields.get("AcctSessionId") or f"{device}:{account}:{occurred:%Y%m%d%H%M}"
        return {
            "observed_account_name": account,
            "asset_identifier": device,
            "asset_address": fields.get("NAS-IP-Address", ""),
            "asset_hint": "network device",
            "occurred_at": occurred,
            "ended_at": occurred,
            "mechanism": UsageObservation.Mechanism.NETWORK_AAA,
            "source_address": fields.get("Calling-Station-ID", ""),
            "privilege_level": fields.get("Privilege-Level") or fields.get("priv-lvl", ""),
            "outcome": "failure" if "fail" in fields.get("Response", "").lower() else "success",
            "session_reference": session,
            "command_count": 1 if command else 0,
            "detail": {"commands": [command] if command else []},
        }


# --------------------------------------------------------------------------
# tac_plus accounting log
# --------------------------------------------------------------------------


@register_collector
class TacPlusLogCollector(TelemetryCollector):
    """
    The classic tac_plus accounting file, for estates not running Identity
    Services Engine. Tab-separated: date, device address, user, port, remote
    address, then key=value pairs including the command.
    """

    key = "tacplus_log"
    display_name = "tac_plus daemon accounting log"
    kind = "network_aaa"
    required_settings = ("path",)

    LINE = re.compile(
        r"^(?P<date>[\d-]+\s[\d:]+)\s+(?P<device>\S+)\s+(?P<user>\S+)\s+(?P<port>\S+)\s+"
        r"(?P<remote>\S+)\s+(?P<rest>.*)$"
    )

    def collect(self, since: datetime) -> Iterator[dict]:
        path = Path(self.settings["path"])
        if not path.exists():
            raise CollectorError(f"{path} does not exist")
        offset = int(self.cursor.get("offset", 0))
        if offset > path.stat().st_size:
            offset = 0

        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            handle.seek(offset)
            for line in handle:
                match = self.LINE.match(line.replace("\t", " ").strip())
                if not match:
                    continue
                occurred = _parse_timestamp(match.group("date"))
                if not occurred or occurred < since:
                    continue
                rest = dict(TACACS_FIELD.findall(match.group("rest")))
                command = rest.get("cmd", "").strip('"')
                yield {
                    "observed_account_name": match.group("user"),
                    "asset_identifier": match.group("device"),
                    "asset_hint": "network device",
                    "occurred_at": occurred,
                    "mechanism": UsageObservation.Mechanism.NETWORK_AAA,
                    "source_address": match.group("remote"),
                    "privilege_level": rest.get("priv-lvl", "").strip('"'),
                    "session_reference": rest.get("task_id", "").strip('"'),
                    "command_count": 1 if command else 0,
                    "detail": {"commands": [command] if command else [], "service": rest.get("service", "")},
                }
            self.cursor = {"offset": handle.tell()}
