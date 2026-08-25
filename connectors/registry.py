"""
Connector catalogue, plugin discovery, and credential resolution.

Three ways to add a platform, in increasing order of effort:

1. **Specification only.** Register `GenericRestConnector` under a new vendor
   key and describe the platform in `PamSystem.options["spec"]`. No code.
2. **Subclass in this package.** Write a class, decorate it with
   `@register_connector`, drop it in `connectors/`. It is discovered on import.
3. **Separate distribution.** Publish a package exposing the entry point group
   `pamsiem.connectors`. Installing it registers the connector; nothing in this
   repository changes. This is the path for a connector that cannot live in this
   codebase or that ships on a different release cadence.

Nothing downstream of `connectors/` knows how many vendors exist.
"""

from __future__ import annotations

import importlib
import json
import logging
import os
import pkgutil
from typing import Mapping, Type

from django.conf import settings

from .base import Capability, PamConnector

log = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "pamsiem.connectors"

_REGISTRY: dict[str, Type[PamConnector]] = {}
_DISCOVERED = False


class CredentialResolutionError(RuntimeError):
    pass


class ConnectorNotRegistered(KeyError):
    pass


def register_connector(connector_class: Type[PamConnector]) -> Type[PamConnector]:
    """Decorator. Registers under `connector_class.vendor`."""
    vendor = getattr(connector_class, "vendor", "")
    if not vendor or vendor == "unknown":
        raise ValueError(f"{connector_class.__name__} must define a unique 'vendor' key")
    existing = _REGISTRY.get(vendor)
    if existing and existing is not connector_class:
        raise ValueError(
            f"Vendor key '{vendor}' is already registered to {existing.__name__}. "
            "Pick a distinct key; it is the stable identifier stored on every platform row."
        )
    _REGISTRY[vendor] = connector_class
    return connector_class


def register_specification_vendor(vendor: str, display_name: str = "") -> Type[PamConnector]:
    """
    Create and register a specification-driven vendor without writing a class.

    Use this when a platform should appear under its own name in the
    configuration screen but the implementation is entirely
    `PamSystem.options["spec"]`:

        register_specification_vendor("acme_vault", "Acme Vault")
    """
    from .generic import GenericRestConnector

    subclass = type(
        f"{vendor.title().replace('_', '')}Connector",
        (GenericRestConnector,),
        {
            "vendor": vendor,
            "display_name": display_name or vendor.replace("_", " ").title(),
            "documentation": "Specification driven. Configure options['spec'].",
            # Without this the dynamic class reports its module as "abc", which
            # is confusing in the connector catalogue.
            "__module__": "connectors.generic",
        },
    )
    return register_connector(subclass)


def _discover() -> None:
    """Import every module in this package, then load installed entry points."""
    global _DISCOVERED
    if _DISCOVERED:
        return
    _DISCOVERED = True

    package = importlib.import_module(__package__)
    for module in pkgutil.iter_modules(package.__path__):
        if module.name in ("base", "registry", "contract"):
            continue
        try:
            importlib.import_module(f"{__package__}.{module.name}")
        except Exception:
            log.exception("Connector module %s failed to import and is unavailable", module.name)

    try:
        from importlib.metadata import entry_points

        for entry in entry_points(group=ENTRY_POINT_GROUP):
            try:
                register_connector(entry.load())
                log.info("Loaded external connector '%s'", entry.name)
            except Exception:
                log.exception("External connector '%s' failed to load", entry.name)
    except Exception:
        log.exception("Entry point discovery failed")

    for vendor, display_name in getattr(settings, "PAM_SPECIFICATION_VENDORS", {}).items():
        if vendor not in _REGISTRY:
            try:
                register_specification_vendor(vendor, display_name)
            except Exception:
                log.exception("Specification vendor '%s' could not be registered", vendor)


def registry() -> Mapping[str, Type[PamConnector]]:
    _discover()
    return dict(_REGISTRY)


def get_connector_class(vendor: str) -> Type[PamConnector]:
    _discover()
    try:
        return _REGISTRY[vendor]
    except KeyError as exc:
        raise ConnectorNotRegistered(
            f"No connector registered for '{vendor}'. Registered: {sorted(_REGISTRY)}"
        ) from exc


def vendor_choices() -> list[tuple[str, str]]:
    return sorted(
        (vendor, cls.display_name or vendor.replace("_", " ").title())
        for vendor, cls in registry().items()
    )


def catalogue() -> list[dict]:
    """Everything the configuration screens and the coverage view need."""
    entries = []
    for vendor, cls in sorted(registry().items()):
        entries.append(
            {
                "vendor": vendor,
                "display_name": cls.display_name or vendor.replace("_", " ").title(),
                "class_path": f"{cls.__module__}.{cls.__qualname__}",
                "capabilities": sorted(cls.capabilities),
                "required_credentials": list(cls.required_credentials),
                "documentation": cls.documentation,
                "specification_driven": any(
                    base.__name__ == "GenericRestConnector" for base in cls.__mro__
                ),
            }
        )
    return entries


def resolve_credentials(reference: str) -> Mapping[str, str]:
    """
    Turn a credential reference stored on a platform row into a usable mapping.

    The database never holds the collector's own credentials. A reference is:
        env:PAM_CYBERARK_PROD     -- JSON object in that environment variable
        file:/run/secrets/ca.json -- JSON object in a mounted secret file

    Add a scheme here to front this with a cloud secret manager.
    """
    if not reference:
        raise CredentialResolutionError("No credential reference configured")
    scheme, _, locator = reference.partition(":")
    if scheme == "env":
        blob = os.environ.get(locator)
        if not blob:
            raise CredentialResolutionError(f"Environment variable {locator} is unset")
    elif scheme == "file":
        try:
            with open(locator, "r", encoding="utf-8") as handle:
                blob = handle.read()
        except OSError as exc:
            raise CredentialResolutionError(f"Cannot read {locator}: {exc}") from exc
    else:
        raise CredentialResolutionError(
            f"Unsupported credential scheme '{scheme}'. Use env: or file:."
        )
    try:
        parsed = json.loads(blob)
    except json.JSONDecodeError as exc:
        raise CredentialResolutionError(
            f"Credential reference {reference} does not contain valid JSON"
        ) from exc
    if not isinstance(parsed, dict):
        raise CredentialResolutionError("Credential reference must contain a JSON object")
    return parsed


def build_connector(system) -> PamConnector:
    connector_class = get_connector_class(system.vendor)
    options = dict(getattr(settings, "PAM_CONNECTOR_DEFAULTS", {}))
    options.update(system.options or {})
    return connector_class(
        base_url=system.base_url,
        credentials=resolve_credentials(system.credential_reference),
        options=options,
    )


def capabilities_for(system) -> frozenset[str]:
    """
    Capabilities without opening a connection.

    Uses the value cached on the platform row when collection has run, so the
    rule engine and the coverage view never need credentials. Falls back to the
    class declaration before the first successful collection.
    """
    cached = getattr(system, "capabilities", None)
    if cached:
        return frozenset(cached)
    try:
        return frozenset(get_connector_class(system.vendor).capabilities)
    except ConnectorNotRegistered:
        return frozenset({Capability.ACCOUNTS})
