"""
Detection engine.

Every rule is a class that yields candidates. The engine reconciles candidates
against stored findings so that a condition holding for six weeks is one
finding aged six weeks, not forty-two alerts.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Iterator

from django.utils import timezone

from connectors.base import Capability
from connectors.registry import capabilities_for
from inventory.models import Finding, ManagedAccount, PamSystem, RuleConfiguration, Severity

log = logging.getLogger(__name__)

_REGISTRY: list[type["Rule"]] = []


def register(rule_class: type["Rule"]) -> type["Rule"]:
    _REGISTRY.append(rule_class)
    return rule_class


@dataclass(slots=True)
class Candidate:
    account: ManagedAccount
    evidence: dict[str, Any] = field(default_factory=dict)
    severity_override: str | None = None
    #: Set when a rule raises several findings against one anchor account --
    #: one per principal, per feed, per unvaulted name. Leave blank when the
    #: account is genuinely the subject.
    subject_key: str = ""


class Rule(ABC):
    rule_id: str = ""
    title: str = ""
    category: str = ""
    severity: str = Severity.MEDIUM
    #: Defaults overridable through RuleConfiguration.parameters.
    defaults: dict[str, Any] = {}
    #: Capabilities the platform must supply for this rule to mean anything.
    #: A rule whose inputs a platform cannot provide is skipped for that
    #: platform and reported as unsupported on the coverage view, rather than
    #: quietly returning nothing and reading as clean.
    requires: frozenset[str] = frozenset({Capability.ACCOUNTS})

    def __init__(self, configuration: RuleConfiguration | None = None):
        self.configuration = configuration
        self.parameters = {**self.defaults, **(configuration.parameters if configuration else {})}

    def parameter(self, name: str) -> Any:
        return self.parameters.get(name)

    @property
    def effective_severity(self) -> str:
        if self.configuration and self.configuration.severity_override:
            return self.configuration.severity_override
        return self.severity

    def supported_system_ids(self) -> list[int]:
        return [
            system.pk
            for system in PamSystem.objects.filter(enabled=True)
            if self.requires <= capabilities_for(system)
        ]

    def base_queryset(self):
        queryset = ManagedAccount.objects.live().select_related("system").filter(
            system_id__in=self.supported_system_ids()
        )
        if self.configuration:
            if self.configuration.exempt_containers:
                queryset = queryset.exclude(container__in=self.configuration.exempt_containers)
            if self.configuration.exempt_account_ids:
                queryset = queryset.exclude(pk__in=self.configuration.exempt_account_ids)
        return queryset

    @abstractmethod
    def evaluate(self) -> Iterator[Candidate]: ...

    def describe(self, candidate: Candidate) -> str:
        return self.title


class RuleEngine:
    def __init__(self, rule_classes: list[type[Rule]] | None = None):
        # Importing the module is what populates the registry. Done here rather
        # than at module scope so that engine.py stays importable by builtin.py.
        from importlib import import_module

        import_module("rules.builtin")
        self.rule_classes = rule_classes or list(_REGISTRY)

    def run(self, system_id: int | None = None) -> dict[str, int]:
        opened = closed = held = skipped = 0
        configurations = {
            configuration.rule_id: configuration
            for configuration in RuleConfiguration.objects.all()
        }

        for rule_class in self.rule_classes:
            configuration = configurations.get(rule_class.rule_id)
            if configuration and not configuration.enabled:
                continue
            rule = rule_class(configuration)

            if not rule.supported_system_ids():
                log.info(
                    "Rule %s covers no enabled platform: needs %s",
                    rule.rule_id,
                    sorted(rule.requires),
                )
                skipped += 1
                continue

            try:
                candidates = list(rule.evaluate())
            except Exception:
                log.exception("Rule %s raised; skipping this cycle", rule_class.rule_id)
                continue

            if system_id is not None:
                candidates = [c for c in candidates if c.account.system_id == system_id]

            current_subjects = {
                (candidate.account.pk, candidate.subject_key) for candidate in candidates
            }

            for candidate in candidates:
                created = self._upsert(rule, candidate)
                opened += int(created)
                held += int(not created)

            closed += self._close_cleared(rule, current_subjects, system_id)

        return {"opened": opened, "still_open": held, "resolved": closed, "unsupported_rules": skipped}

    def _upsert(self, rule: Rule, candidate: Candidate) -> bool:
        now = timezone.now()
        existing = Finding.objects.filter(
            rule_id=rule.rule_id,
            account=candidate.account,
            subject_key=candidate.subject_key,
            state__in=[Finding.State.OPEN, Finding.State.ACKNOWLEDGED, Finding.State.SUPPRESSED],
        ).first()

        if existing:
            existing.last_seen_at = now
            existing.evidence = candidate.evidence
            existing.severity = candidate.severity_override or rule.effective_severity
            existing.exported_at = None  # re-export on material change
            existing.save(update_fields=["last_seen_at", "evidence", "severity", "exported_at"])
            return False

        Finding.objects.create(
            rule_id=rule.rule_id,
            subject_key=candidate.subject_key,
            title=rule.describe(candidate),
            category=rule.category,
            severity=candidate.severity_override or rule.effective_severity,
            account=candidate.account,
            system=candidate.account.system,
            opened_at=now,
            last_seen_at=now,
            evidence=candidate.evidence,
        )
        return True

    def _close_cleared(self, rule: Rule, current_subjects: set[tuple[int, str]], system_id: int | None) -> int:
        # Scoped to the platforms this rule actually covers. Losing a capability
        # (an audit feed switched off, say) must not silently resolve every
        # finding the rule had already raised there.
        stale = Finding.objects.filter(
            rule_id=rule.rule_id,
            state__in=[Finding.State.OPEN, Finding.State.ACKNOWLEDGED],
            system_id__in=rule.supported_system_ids(),
        )
        if system_id is not None:
            stale = stale.filter(system_id=system_id)
        stale = stale.exclude(
            pk__in=[
                finding.pk
                for finding in stale
                if (finding.account_id, finding.subject_key) in current_subjects
            ]
        )
        return stale.update(
            state=Finding.State.RESOLVED,
            resolved_at=timezone.now(),
            exported_at=None,
        )
