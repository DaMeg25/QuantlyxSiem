"""
Read-only enumeration of who holds what on a resource platform.

Same constraints as the credential connectors, for the same reasons: these
enumerate access, they never read code, never read secret values, and never
write. A connector that could add a collaborator would make this system a
provisioning path, and the whole design rests on it not being one.
"""

from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterator, Mapping, Optional

from connectors.base import build_session, ConnectorError, scrub

log = logging.getLogger(__name__)

#: Paths that return secret values or source code on the supported platforms.
BLOCKED_PATTERNS = (
    r"/actions/secrets", r"/actions/variables", r"/codespaces/secrets",
    r"/dependabot/secrets", r"/variables(/|$)", r"/secure_files",
    r"/repository/files/", r"/archive(\.|/)", r"/contents/", r"/raw/",
)
_BLOCKED = re.compile("|".join(BLOCKED_PATTERNS), re.IGNORECASE)


class ResourceAccessBlocked(RuntimeError):
    """Raised when connector code reaches for secrets or source rather than access."""


@dataclass(slots=True)
class NormalizedResource:
    identifier: str
    display_name: str = ""
    url: str = ""
    production: bool = False
    archived: bool = False
    owner_identity: str = ""
    owner_team: str = ""
    criticality: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.detail = scrub(self.detail)


@dataclass(slots=True)
class NormalizedAccess:
    """One principal holding one level of access on one resource."""

    resource_identifier: str
    principal_identifier: str
    access_level: str
    principal_type: str = "unknown"
    display_name: str = ""
    email: str = ""
    granted_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    #: True for deploy keys, machine users, installed applications, and tokens.
    machine_identity: bool = False
    detail: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.detail = scrub(self.detail)


class ResourceConnector(ABC):
    platform: str = ""
    display_name: str = ""
    required_credentials: tuple[str, ...] = ()
    documentation: str = ""

    def __init__(self, *, base_url: str, credentials: Mapping[str, str], options: Mapping[str, Any] | None = None):
        self.base_url = base_url.rstrip("/")
        self._credentials = dict(credentials)
        self.options = dict(options or {})
        self.session = build_session(verify=self.options.get("tls_verify", True))
        self.page_size = int(self.options.get("page_size", 100))
        self.timeout = float(self.options.get("timeout_seconds", 30))
        missing = [key for key in self.required_credentials if not self._credentials.get(key)]
        if missing:
            raise ConnectorError(f"{self.platform} connector needs credential keys {sorted(missing)}")

    def _url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"

    def _get(self, path: str, **kwargs) -> Any:
        if _BLOCKED.search(path):
            raise ResourceAccessBlocked(
                f"Refusing {path}: this endpoint returns secrets or source, not access."
            )
        response = self.session.get(self._url(path), timeout=self.timeout, **kwargs)
        if response.status_code >= 400:
            raise ConnectorError(f"{path} returned {response.status_code}: {response.text[:300]}")
        return response.json() if response.content else []

    def _paged(self, path: str, params: dict | None = None) -> Iterator[dict]:
        page = 1
        while True:
            payload = self._get(path, params={**(params or {}), "per_page": self.page_size, "page": page})
            items = payload if isinstance(payload, list) else payload.get("values") or payload.get("value") or []
            if not items:
                return
            yield from items
            if len(items) < self.page_size:
                return
            page += 1
            if page > int(self.options.get("maximum_pages", 200)):
                log.warning("Pagination guard reached on %s", path)
                return

    @abstractmethod
    def authenticate(self) -> None: ...

    @abstractmethod
    def iter_resources(self) -> Iterator[NormalizedResource]: ...

    @abstractmethod
    def iter_access(self, resource_identifier: str) -> Iterator[NormalizedAccess]: ...

    def close(self) -> None:
        try:
            self.session.close()
        except Exception:  # pragma: no cover
            pass

    def __enter__(self):
        self.authenticate()
        return self

    def __exit__(self, *exc) -> None:
        self.close()


_REGISTRY: dict[str, type[ResourceConnector]] = {}


def register_resource_connector(cls: type[ResourceConnector]) -> type[ResourceConnector]:
    if not cls.platform:
        raise ValueError(f"{cls.__name__} needs a platform key")
    _REGISTRY[cls.platform] = cls
    return cls


def resource_registry() -> Mapping[str, type[ResourceConnector]]:
    from importlib import import_module
    import pkgutil

    package = import_module(__package__)
    for module in pkgutil.iter_modules(package.__path__):
        if module.name != "base":
            try:
                import_module(f"{__package__}.{module.name}")
            except Exception:
                log.exception("Resource connector module %s failed to import", module.name)
    return dict(_REGISTRY)
