"""
Parsers for target-side authentication telemetry.

These records do not come from a vault. They come from the systems being logged
in to, which is exactly why they see logins the vault never brokered. In a bank
they normally arrive through the enterprise event platform rather than by
querying each device, so every parser here takes an already-exported file or
stream and does no network work of its own.

Supported today:

  * Cisco TACACS+ accounting from Identity Services Engine. The richest feed for
    network estates: it names the device, the account, the privilege level, and
    every command entered.
  * Windows security events 4624 and 4625, as exported JSON lines.
  * Unix authentication and privilege escalation, from syslog-style text.
  * Database audit, as comma-separated exports.

Adding a fifth means writing one generator that yields the same dictionary
shape. Nothing downstream changes.
"""

from __future__ import annotations

import csv
import json
import logging
import re
from datetime import datetime, timezone as datetime_timezone
from pathlib import Path
from typing import Iterator

from django.utils import timezone

from inventory.models import UsageObservation

log = logging.getLogger(__name__)

MECHANISM_AAA = UsageObservation.Mechanism.NETWORK_AAA
MECHANISM_TARGET = UsageObservation.Mechanism.TARGET_AUTHENTICATION

#: Windows logon types that represent an interactive or remote administrative
#: session. Service and batch logons are excluded: they are noise for this
#: purpose and would swamp the correlation pass.
INTERESTING_LOGON_TYPES = {"2", "3", "7", "10", "11"}


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if timezone.is_naive(value):
        return value.replace(tzinfo=datetime_timezone.utc)
    return value


def _parse_timestamp(raw: str) -> datetime | None:
    if not raw:
        return None
    text = raw.strip().replace("Z", "+00:00")
    for parser in (
        lambda value: datetime.fromisoformat(value),
        lambda value: datetime.strptime(value, "%Y-%m-%d %H:%M:%S"),
        lambda value: datetime.strptime(value, "%b %d %H:%M:%S").replace(
            year=timezone.now().year
        ),
        lambda value: datetime.strptime(value, "%m/%d/%Y %I:%M:%S %p"),
    ):
        try:
            return _aware(parser(text))
        except (ValueError, TypeError):
            continue
    log.debug("Unparsable timestamp: %r", raw)
    return None


# --------------------------------------------------------------------------
# Cisco TACACS+ accounting, as exported by Identity Services Engine
# --------------------------------------------------------------------------

# Hyphens are everywhere in these field names -- Privilege-Level, NAS-IP-Address,
# Calling-Station-ID, User-Name. A key pattern of \w+ matches the tail of each
# and silently drops the rest, which reads as "the device did not send it".
TACACS_FIELD = re.compile(r"([\w-]+)=((?:\"[^\"]*\")|(?:\S+))")


def parse_tacacs_accounting(path: str | Path) -> Iterator[dict]:
    """
    Accepts either the key=value accounting format or a comma-separated export.

    The fields that matter: NetworkDeviceName (the device), UserName (the
    account), Privilege-Level, CmdSet or Command (what was run), and the
    session identifier, which lets a login and its commands roll up into one
    observation rather than one per command.
    """
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    first = text.lstrip().splitlines()[0] if text.strip() else ""

    if "," in first and "=" not in first:
        yield from _tacacs_from_csv(text)
        return

    sessions: dict[str, dict] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = {
            key: value.strip('"') for key, value in TACACS_FIELD.findall(line)
        }
        if not fields:
            continue

        device = fields.get("NetworkDeviceName") or fields.get("nas-ip-address") or fields.get("NAS-IP-Address")
        account = fields.get("UserName") or fields.get("User-Name") or fields.get("user")
        occurred = _parse_timestamp(fields.get("Timestamp") or fields.get("time") or "")
        if not device or not account or not occurred:
            continue

        session = fields.get("AcctSessionId") or fields.get("session_id") or f"{device}:{account}:{occurred:%Y%m%d%H%M}"
        record = sessions.setdefault(
            session,
            {
                "observed_account_name": account,
                "asset_identifier": device,
                "asset_address": fields.get("NAS-IP-Address", ""),
                "asset_hint": "network device",
                "occurred_at": occurred,
                "mechanism": MECHANISM_AAA,
                "source_address": fields.get("Calling-Station-ID") or fields.get("remote_address", ""),
                "privilege_level": fields.get("Privilege-Level") or fields.get("priv-lvl", ""),
                "outcome": "failure" if "fail" in (fields.get("Response", "").lower()) else "success",
                "session_reference": session,
                "command_count": 0,
                "detail": {"commands": []},
            },
        )
        command = fields.get("CmdSet") or fields.get("Command") or fields.get("cmd")
        if command:
            record["command_count"] += 1
            if len(record["detail"]["commands"]) < 25:
                record["detail"]["commands"].append(command)
        record["ended_at"] = occurred
        record["occurred_at"] = min(record["occurred_at"], occurred)

    yield from sessions.values()


def _tacacs_from_csv(text: str) -> Iterator[dict]:
    reader = csv.DictReader(text.splitlines())
    for row in reader:
        occurred = _parse_timestamp(row.get("Timestamp") or row.get("Date") or "")
        device = row.get("NetworkDeviceName") or row.get("Device") or ""
        account = row.get("UserName") or row.get("User") or ""
        if not (occurred and device and account):
            continue
        yield {
            "observed_account_name": account,
            "asset_identifier": device,
            "asset_address": row.get("NASIPAddress", ""),
            "asset_hint": "network device",
            "occurred_at": occurred,
            "mechanism": MECHANISM_AAA,
            "source_address": row.get("RemoteAddress", ""),
            "privilege_level": row.get("PrivilegeLevel", ""),
            "outcome": "failure" if str(row.get("Response", "")).lower().startswith("fail") else "success",
            "session_reference": row.get("AcctSessionId", ""),
            "detail": {"command": row.get("CmdSet", "")},
        }


# --------------------------------------------------------------------------
# Windows security events
# --------------------------------------------------------------------------


def parse_windows_security(path: str | Path) -> Iterator[dict]:
    """
    JSON lines as most event platforms export them. Event 4624 is a successful
    logon, 4625 a failure. Machine accounts and service logons are dropped --
    they are the overwhelming majority of the volume and none of the signal.
    """
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        event_id = str(event.get("EventID") or event.get("event_id") or "")
        if event_id not in ("4624", "4625"):
            continue

        account = event.get("TargetUserName") or event.get("target_user") or ""
        if not account or account.endswith("$") or account.upper() in ("SYSTEM", "ANONYMOUS LOGON"):
            continue

        logon_type = str(event.get("LogonType") or event.get("logon_type") or "")
        if logon_type and logon_type not in INTERESTING_LOGON_TYPES:
            continue

        occurred = _parse_timestamp(
            event.get("TimeCreated") or event.get("@timestamp") or event.get("timestamp") or ""
        )
        host = event.get("Computer") or event.get("host") or ""
        if not (occurred and host):
            continue

        yield {
            "observed_account_name": account,
            "asset_identifier": host,
            "asset_hint": "server windows",
            "occurred_at": occurred,
            "mechanism": MECHANISM_TARGET,
            "source_address": event.get("IpAddress") or event.get("source_ip") or "",
            "outcome": "success" if event_id == "4624" else "failure",
            "session_reference": str(event.get("LogonId") or ""),
            "detail": {
                "logon_type": logon_type,
                "domain": event.get("TargetDomainName", ""),
                "process": event.get("ProcessName", ""),
            },
        }


# --------------------------------------------------------------------------
# Unix authentication and privilege escalation
# --------------------------------------------------------------------------

SSH_ACCEPT = re.compile(
    r"^(?P<time>\w{3}\s+\d+\s[\d:]+)\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"(?P<result>Accepted|Failed)\s+\S+\s+for\s+(?P<user>\S+)\s+from\s+(?P<address>\S+)"
)
SUDO_LINE = re.compile(
    r"^(?P<time>\w{3}\s+\d+\s[\d:]+)\s+(?P<host>\S+)\s+sudo:\s+(?P<user>\S+)\s+:.*?COMMAND=(?P<command>.+)$"
)


def parse_unix_auth(path: str | Path) -> Iterator[dict]:
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        ssh = SSH_ACCEPT.match(line)
        if ssh:
            occurred = _parse_timestamp(ssh.group("time"))
            if not occurred:
                continue
            yield {
                "observed_account_name": ssh.group("user"),
                "asset_identifier": ssh.group("host"),
                "asset_hint": "server unix",
                "occurred_at": occurred,
                "mechanism": MECHANISM_TARGET,
                "source_address": ssh.group("address"),
                "outcome": "success" if ssh.group("result") == "Accepted" else "failure",
                "detail": {"service": "sshd"},
            }
            continue

        sudo = SUDO_LINE.match(line)
        if sudo:
            occurred = _parse_timestamp(sudo.group("time"))
            if not occurred:
                continue
            yield {
                "observed_account_name": sudo.group("user"),
                "asset_identifier": sudo.group("host"),
                "asset_hint": "server unix",
                "occurred_at": occurred,
                "mechanism": MECHANISM_TARGET,
                "outcome": "success",
                "privilege_level": "root",
                "detail": {"service": "sudo", "command": sudo.group("command")[:400]},
            }


# --------------------------------------------------------------------------
# Database audit
# --------------------------------------------------------------------------


def parse_database_audit(path: str | Path) -> Iterator[dict]:
    """Comma-separated audit export: timestamp, instance, username, client address, action."""
    reader = csv.DictReader(Path(path).read_text(encoding="utf-8", errors="replace").splitlines())
    for row in reader:
        occurred = _parse_timestamp(row.get("timestamp") or row.get("event_time") or "")
        instance = row.get("instance") or row.get("db_name") or ""
        account = row.get("username") or row.get("db_user") or ""
        if not (occurred and instance and account):
            continue
        yield {
            "observed_account_name": account,
            "asset_identifier": instance,
            "asset_hint": "database",
            "occurred_at": occurred,
            "mechanism": MECHANISM_TARGET,
            "source_address": row.get("client_address", ""),
            "outcome": row.get("outcome", "success"),
            "detail": {"action": row.get("action", "")},
        }


PARSERS = {
    "network_aaa": parse_tacacs_accounting,
    "windows_auth": parse_windows_security,
    "unix_auth": parse_unix_auth,
    "database_audit": parse_database_audit,
}
