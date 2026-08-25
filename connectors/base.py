"""
Common contract for every Privileged Access Management connector.

Design constraint that everything else depends on: this collector reads
*metadata about* credentials. It never reads credential values. That is
enforced structurally, not by convention:

  1. MetadataOnlySession refuses to issue a request whose path matches a
     known secret-retrieval endpoint on any supported vendor.
  2. scrub() strips value-bearing fields out of every raw payload before it
     is handed to the persistence layer.

Consequence: a compromise of this dashboard yields an inventory of which
privileged accounts exist and how well they are governed. It does not yield
a single usable credential. Keep it that way -- if a future requirement asks
for a credential value, that requirement belongs in a separate system with
its own break-glass controls, not here.
"""

from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterator, Mapping, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger(__name__)


class SecretRetrievalBlocked(RuntimeError):
    """Raised when connector code attempts to reach a credential-value endpoint."""


class ConnectorError(RuntimeError):
    """Transport, authentication, or contract failure against a vendor."""


# Paths that return a credential value on one or more supported platforms.
# Matched case-insensitively against the request path.
BLOCKED_PATH_PATTERNS: tuple[str, ...] = (
    r"/accounts?/[^/]+/password/retrieve",
    r"/accounts?/[^/]+/secret",
    r"/managedaccounts/[^/]+/credentials",
    r"/credentials(/|$)",
    r"/secrets?/[^/]+/fields/(password|private-?key|passphrase)",
    r"/secrets?/[^/]+/restricted",
    r"/getpassword",
    r"/aimwebservice",
    r"/passwordvault/webservices/pimservices\.svc/accounts/[^/]+/credentials",
    r"/requests/[^/]+/checkout",
    r"/static-creds(/|$)",
    r"/creds(/|$)",
)

_BLOCKED = re.compile("|".join(BLOCKED_PATH_PATTERNS), re.IGNORECASE)

# Field names whose values are never persisted, at any nesting depth.
SECRET_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "password",
        "newpassword",
        "currentpassword",
        "secret",
        "secretvalue",
        "passphrase",
        "privatekey",
        "private_key",
        "sshkey",
        "ssh_key",
        "certificate",
        "pfx",
        "pkcs12",
        "token",
        "accesstoken",
        "access_token",
        "refreshtoken",
        "refresh_token",
        "clientsecret",
        "client_secret",
        "apikey",
        "api_key",
        "authorization",
        "cookie",
        "sessiontoken",
        "client_token",
    }
)

REDACTED = "[redacted-by-collector]"


def scrub(value: Any, _depth: int = 0) -> Any:
    """Recursively replace value-bearing fields with a redaction marker."""
    if _depth > 12:
        return REDACTED
    if isinstance(value, Mapping):
        out = {}
        for key, item in value.items():
            if str(key).replace("-", "").replace("_", "").lower() in SECRET_FIELD_NAMES:
                out[key] = REDACTED
            else:
                out[key] = scrub(item, _depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [scrub(item, _depth + 1) for item in value]
    return value


class MetadataOnlySession(requests.Session):
    """A requests Session that will not call a credential-retrieval endpoint."""

    def request(self, method, url, *args, **kwargs):  # type: ignore[override]
        path = requests.utils.urlparse(url).path
        if _BLOCKED.search(path):
            raise SecretRetrievalBlocked(
                f"Refusing {method} {path}: this path returns a credential value. "
                "The collector is metadata-only."
            )
        return super().request(method, url, *args, **kwargs)


def build_session(
    verify: bool | str = True,
    timeout_connect: float = 5.0,
    total_retries: int = 3,
    backoff: float = 1.5,
    user_agent: str = "pam-lifecycle-collector/1.0",
) -> MetadataOnlySession:
    session = MetadataOnlySession()
    session.verify = verify
    session.headers.update({"User-Agent": user_agent, "Accept": "application/json"})
    retry = Retry(
        total=total_retries,
        backoff_factor=backoff,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET", "POST"}),
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_maxsize=16)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.request_timeout = timeout_connect  # type: ignore[attr-defined]
    return session


# Normalized vocabulary. Every vendor is mapped onto these values so that
# rules and dashboards never contain a vendor-specific branch.

ACCOUNT_KIND_HUMAN = "human"
ACCOUNT_KIND_SERVICE = "service"
ACCOUNT_KIND_BOT = "bot"
ACCOUNT_KIND_APPLICATION = "application"
ACCOUNT_KIND_BREAK_GLASS = "break_glass"
ACCOUNT_KIND_VENDOR = "vendor"
ACCOUNT_KIND_UNKNOWN = "unknown"

NON_HUMAN_KINDS = frozenset(
    {ACCOUNT_KIND_SERVICE, ACCOUNT_KIND_BOT, ACCOUNT_KIND_APPLICATION}
)

STATUS_ACTIVE = "active"
STATUS_DISABLED = "disabled"
STATUS_PENDING_DELETE = "pending_delete"
STATUS_DELETED = "deleted"
STATUS_UNKNOWN = "unknown"


class Capability(str):
    """
    What a platform can actually tell us.

    This exists because an absent field and an unsupported field look identical
    downstream, and treating them the same is how a blind spot gets reported as
    compliance. A connector declares what it can supply; the rule engine skips
    rules whose inputs the platform cannot provide, and the coverage view shows
    exactly which detections are inert where.
    """

    ACCOUNTS = "accounts"                    # inventory; every connector has this
    ACTIVITY = "activity"                    # audit feed of retrievals and changes
    ROTATION_INTERVAL = "rotation_interval"  # the policy interval, not just the last change
    VERIFICATION = "verification"            # vault-versus-target reconciliation state
    USAGE_TIMESTAMPS = "usage_timestamps"    # last-used, for dormancy
    OWNERSHIP = "ownership"                  # an owner attribute on the account
    ENTITLEMENTS = "entitlements"            # how many identities can reach the account
    DISCOVERY = "discovery"                  # unvaulted accounts found on targets
    TICKET_REFERENCE = "ticket_reference"    # change-ticket captured at retrieval
    SESSION_TARGETS = "session_targets"      # which asset a brokered session reached
    APPLICATION_IDENTITY = "application_identity"  # which application fetched a credential

    ALL = (
        ACCOUNTS, ACTIVITY, ROTATION_INTERVAL, VERIFICATION, USAGE_TIMESTAMPS,
        OWNERSHIP, ENTITLEMENTS, DISCOVERY, TICKET_REFERENCE,
        SESSION_TARGETS, APPLICATION_IDENTITY,
    )


@dataclass(slots=True)
class NormalizedAccount:
    """One managed privileged account, in the shape the warehouse stores."""

    external_id: str
    username: str
    container: str = ""              # safe, folder, or namespace on the vendor
    target_address: str = ""         # host, database, or directory the account lives on
    platform: str = ""               # vendor policy or platform identifier
    kind: str = ACCOUNT_KIND_UNKNOWN
    status: str = STATUS_UNKNOWN

    owner_identity: str = ""         # person or distribution list accountable for it
    owner_team: str = ""
    business_application: str = ""

    onboarded_at: Optional[datetime] = None
    last_rotation_at: Optional[datetime] = None
    next_rotation_due: Optional[datetime] = None
    rotation_interval_days: Optional[int] = None
    auto_rotation_enabled: Optional[bool] = None

    last_verification_at: Optional[datetime] = None
    verification_ok: Optional[bool] = None
    last_rotation_failed: bool = False
    rotation_failure_reason: str = ""

    last_used_at: Optional[datetime] = None
    exclusive_checkout: Optional[bool] = None
    entitled_identity_count: Optional[int] = None

    raw: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.raw = scrub(self.raw)


@dataclass(slots=True)
class NormalizedUsage:
    """
    A login the vault can vouch for: a session it brokered, or a credential
    fetch by a named application. Distinct from NormalizedActivity, which
    records that a credential was handed out -- this records where it went.
    """

    external_id: str
    account_external_id: str
    asset_identifier: str          # device, host, database, or application reached
    occurred_at: datetime
    ended_at: Optional[datetime] = None
    actor: str = ""
    source_address: str = ""
    outcome: str = "success"
    mechanism: str = "brokered_session"
    session_reference: str = ""
    command_count: Optional[int] = None
    asset_hint: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.raw = scrub(self.raw)


@dataclass(slots=True)
class NormalizedActivity:
    """One audit event about an account. Never contains a credential value."""

    external_id: str
    account_external_id: str
    action: str
    occurred_at: datetime
    actor: str = ""
    source_address: str = ""
    outcome: str = ""
    reason: str = ""
    ticket_reference: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.raw = scrub(self.raw)


class PamConnector(ABC):
    """
    Implement one subclass per vendor.

    Contract:
      * authenticate() is idempotent and may be called again after a 401.
      * iter_accounts() yields the complete current inventory. It must page
        through the whole result set; partial inventories cause the reconciler
        to mark live accounts as deleted.
      * iter_activity(since) yields audit events at or after `since`. Return an
        empty iterator if the vendor exposes no activity endpoint.
      * Neither method may request a credential value.
    """

    #: Stable machine key. Must be unique across the registry.
    vendor: str = "unknown"
    #: Shown in the configuration screens.
    display_name: str = ""
    #: What this platform can supply. Rules that need something absent here are
    #: skipped for this platform rather than silently returning nothing.
    capabilities: frozenset[str] = frozenset({Capability.ACCOUNTS})
    #: Keys expected in the resolved credential mapping, validated before use.
    required_credentials: tuple[str, ...] = ()
    #: Free text shown next to the connector in the catalogue.
    documentation: str = ""

    def __init__(self, *, base_url: str, credentials: Mapping[str, str], options: Mapping[str, Any] | None = None):
        self.base_url = base_url.rstrip("/")
        self._credentials = credentials
        self.options = dict(options or {})
        self.session = build_session(verify=self.options.get("tls_verify", True))
        self.page_size = int(self.options.get("page_size", 250))
        self.timeout = float(self.options.get("timeout_seconds", 30))
        self.validate_credentials()

    def validate_credentials(self) -> None:
        missing = [key for key in self.required_credentials if not self._credentials.get(key)]
        if missing:
            raise ConnectorError(
                f"{self.vendor} connector needs credential keys {sorted(missing)}; "
                "add them to the JSON object behind this platform's credential reference"
            )

    def declared_capabilities(self) -> frozenset[str]:
        """
        Capabilities as configured. A deployment can subtract one it has not
        licensed or enabled -- for example an audit feed it has not turned on --
        through options["disabled_capabilities"].
        """
        removed = set(self.options.get("disabled_capabilities", []))
        added = set(self.options.get("extra_capabilities", []))
        return frozenset((set(self.capabilities) | added) - removed)

    # -- helpers ---------------------------------------------------------

    def _url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"

    def _get(self, path: str, **kwargs) -> Any:
        response = self.session.get(self._url(path), timeout=self.timeout, **kwargs)
        return self._json_or_raise(response)

    def _post(self, path: str, **kwargs) -> Any:
        response = self.session.post(self._url(path), timeout=self.timeout, **kwargs)
        return self._json_or_raise(response)

    @staticmethod
    def _json_or_raise(response: requests.Response) -> Any:
        if response.status_code >= 400:
            raise ConnectorError(
                f"{response.request.method} {response.request.path_url} "
                f"returned {response.status_code}: {response.text[:400]}"
            )
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError as exc:
            raise ConnectorError(f"Non-JSON response from {response.url}") from exc

    @staticmethod
    def epoch_to_datetime(value: Any) -> Optional[datetime]:
        """Vendors emit Unix seconds, Unix milliseconds, or nothing."""
        if value in (None, "", 0):
            return None
        try:
            number = float(value)
        except (TypeError, ValueError):
            return None
        if number > 1e11:  # milliseconds
            number = number / 1000.0
        try:
            return datetime.fromtimestamp(number, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None

    @staticmethod
    def iso_to_datetime(value: Any) -> Optional[datetime]:
        if not value or not isinstance(value, str):
            return None
        text = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed

    def classify_kind(self, *, username: str, platform: str, container: str, hints: Mapping[str, Any] | None = None) -> str:
        """
        Map a vendor account onto the normalized account kind.

        Classification drives most of the rule set, so it is deliberately
        configurable per deployment rather than hard-coded. Supply
        options["kind_patterns"] as a list of [regex, kind] pairs; the first
        match against "<container>/<platform>/<username>" wins.
        """
        subject = f"{container}/{platform}/{username}".lower()
        for pattern, kind in self.options.get("kind_patterns", []):
            if re.search(pattern, subject, re.IGNORECASE):
                return kind
        hints = hints or {}
        if hints.get("is_application") or hints.get("application_id"):
            return ACCOUNT_KIND_APPLICATION
        if re.search(r"(^|[_.-])(svc|srv|service|app|batch|job|robot|bot|rpa|daemon)([_.-]|\d|$)", subject):
            return ACCOUNT_KIND_SERVICE
        if re.search(r"(break.?glass|firecall|emergency)", subject):
            return ACCOUNT_KIND_BREAK_GLASS
        if re.search(r"(vendor|thirdparty|third.party|contractor)", subject):
            return ACCOUNT_KIND_VENDOR
        if re.search(r"(^|[_.-])(adm|admin|priv|da|sa)([_.-]|\d|$)", subject):
            return ACCOUNT_KIND_HUMAN
        return ACCOUNT_KIND_UNKNOWN

    # -- contract --------------------------------------------------------

    @abstractmethod
    def authenticate(self) -> None: ...

    @abstractmethod
    def iter_accounts(self) -> Iterator[NormalizedAccount]: ...

    def iter_activity(self, since: datetime) -> Iterator[NormalizedActivity]:
        return iter(())

    def iter_usage(self, since: datetime) -> Iterator["NormalizedUsage"]:
        """
        Sessions the vault brokered, and credential fetches by applications.

        Return an empty iterator if the platform does not proxy sessions. This
        is tier one and tier two of the usage picture; tier three arrives
        through usage/ingest.py from the targets themselves.
        """
        return iter(())

    def close(self) -> None:
        try:
            self.session.close()
        except Exception:  # pragma: no cover
            log.debug("Session close failed for %s", self.vendor, exc_info=True)

    def __enter__(self) -> "PamConnector":
        self.authenticate()
        return self

    def __exit__(self, *exc) -> None:
        self.close()
