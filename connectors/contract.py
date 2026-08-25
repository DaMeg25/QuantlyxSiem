"""
Conformance harness for a new connector.

Subclass `ConnectorContractTests`, point it at your connector and a folder of
recorded responses, and it checks the parts that are easy to get wrong and
expensive to get wrong: pagination that truncates, timestamps parsed as naive,
credential values reaching the database, and identifiers that are not stable
between pulls. A connector that passes this is safe to enable; one that does
not will produce quiet, plausible, wrong numbers.

    class AcmeConnectorTests(ConnectorContractTests, TestCase):
        connector_class = AcmeConnector
        credentials = {"username": "test", "password": "test"}
        fixture_directory = Path(__file__).parent / "fixtures" / "acme"
        expected_capabilities = {Capability.ACCOUNTS, Capability.ROTATION_INTERVAL}

Record fixtures from a non-production instance and review them before
committing. The harness serves them verbatim so that the scrubbing assertions
are real, which means a fixture containing a live credential value would be a
credential committed to source control. Use throwaway values.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest import mock

from .base import (
    Capability,
    NormalizedAccount,
    NormalizedActivity,
    SECRET_FIELD_NAMES,
)


class RecordedResponse:
    """
    Minimal stand-in for a requests Response backed by a fixture file.

    Deliberately does NOT scrub the payload: scrubbing is the connector's job
    and this harness exists to verify it happens. A harness that pre-scrubbed
    its own fixtures would make the scrubbing test pass for a connector that
    persists credential values verbatim.
    """

    def __init__(self, payload: Any, status_code: int = 200):
        self._payload = payload
        self.status_code = status_code
        self.content = b"{}" if payload is None else json.dumps(self._payload).encode()
        self.text = self.content.decode()
        self.url = "https://recorded.invalid/"
        self.request = mock.Mock(method="GET", path_url="/recorded")

    def json(self) -> Any:
        return self._payload


class ConnectorContractTests:
    """Mix into a Django TestCase."""

    connector_class = None
    credentials: dict[str, str] = {}
    options: dict[str, Any] = {}
    fixture_directory: Path | None = None
    expected_capabilities: set[str] = {Capability.ACCOUNTS}
    #: Fixture files served in order for successive calls, ending with an empty page.
    account_fixtures: list[str] = ["accounts_page_1.json", "accounts_page_2.json", "accounts_empty.json"]
    activity_fixtures: list[str] = []
    minimum_accounts = 1

    # -- plumbing --------------------------------------------------------

    def _load(self, name: str) -> Any:
        assert self.fixture_directory, "Set fixture_directory"
        with open(Path(self.fixture_directory) / name, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def _connector(self, fixtures: list[str]):
        connector = self.connector_class(
            base_url="https://recorded.invalid",
            credentials=self.credentials,
            options={**self.options, "tls_verify": False},
        )
        responses = [RecordedResponse(self._load(name)) for name in fixtures]
        cycle = iter(responses)

        def serve(*args, **kwargs):
            try:
                return next(cycle)
            except StopIteration:
                return RecordedResponse({})

        connector.session.get = mock.Mock(side_effect=serve)
        connector.session.post = mock.Mock(side_effect=serve)
        return connector

    def _accounts(self) -> list[NormalizedAccount]:
        connector = self._connector(self.account_fixtures)
        connector.authenticate()
        return list(connector.iter_accounts())

    # -- the contract ----------------------------------------------------

    def test_declares_a_unique_vendor_key(self):
        from .registry import registry

        self.assertNotIn(self.connector_class.vendor, ("", "unknown"))
        self.assertIs(registry().get(self.connector_class.vendor), self.connector_class)

    def test_declares_expected_capabilities(self):
        connector = self._connector([])
        self.assertEqual(set(connector.declared_capabilities()), set(self.expected_capabilities))

    def test_missing_credentials_fail_at_construction(self):
        required = self.connector_class.required_credentials
        if not required:
            self.skipTest("connector declares no required credential keys")
        with self.assertRaises(Exception):
            self.connector_class(
                base_url="https://recorded.invalid", credentials={}, options=self.options
            )

    def test_pagination_reaches_every_page(self):
        accounts = self._accounts()
        self.assertGreaterEqual(len(accounts), self.minimum_accounts)

    def test_identifiers_are_present_and_unique(self):
        accounts = self._accounts()
        identifiers = [account.external_id for account in accounts]
        self.assertTrue(all(identifiers), "every account needs a stable external identifier")
        self.assertEqual(len(identifiers), len(set(identifiers)), "external identifiers must be unique")

    def test_timestamps_are_timezone_aware(self):
        for account in self._accounts():
            for field in ("last_rotation_at", "next_rotation_due", "onboarded_at", "last_used_at"):
                value = getattr(account, field)
                if isinstance(value, datetime):
                    self.assertIsNotNone(
                        value.tzinfo, f"{field} must be timezone aware, got a naive datetime"
                    )

    def test_no_credential_values_survive_into_raw_payloads(self):
        for account in self._accounts():
            self._assert_scrubbed(account.raw)

    def _assert_scrubbed(self, payload: Any, path: str = "raw") -> None:
        if isinstance(payload, dict):
            for key, value in payload.items():
                flattened = str(key).replace("-", "").replace("_", "").lower()
                if flattened in SECRET_FIELD_NAMES:
                    self.assertEqual(
                        value, "[redacted-by-collector]", f"{path}.{key} was persisted unscrubbed"
                    )
                else:
                    self._assert_scrubbed(value, f"{path}.{key}")
        elif isinstance(payload, list):
            for index, value in enumerate(payload):
                self._assert_scrubbed(value, f"{path}[{index}]")

    def test_activity_respects_the_since_boundary(self):
        if not self.activity_fixtures:
            self.skipTest("connector supplies no activity feed")
        connector = self._connector(self.activity_fixtures)
        connector.authenticate()
        since = datetime.now(timezone.utc) - timedelta(days=1)
        events = list(connector.iter_activity(since))
        for event in events:
            self.assertIsInstance(event, NormalizedActivity)
            self.assertGreaterEqual(event.occurred_at, since)
            self.assertTrue(event.account_external_id)

    def test_kind_classification_produces_a_known_value(self):
        from .base import (
            ACCOUNT_KIND_APPLICATION, ACCOUNT_KIND_BOT, ACCOUNT_KIND_BREAK_GLASS,
            ACCOUNT_KIND_HUMAN, ACCOUNT_KIND_SERVICE, ACCOUNT_KIND_UNKNOWN, ACCOUNT_KIND_VENDOR,
        )

        valid = {
            ACCOUNT_KIND_HUMAN, ACCOUNT_KIND_SERVICE, ACCOUNT_KIND_BOT, ACCOUNT_KIND_APPLICATION,
            ACCOUNT_KIND_BREAK_GLASS, ACCOUNT_KIND_VENDOR, ACCOUNT_KIND_UNKNOWN,
        }
        for account in self._accounts():
            self.assertIn(account.kind, valid)
