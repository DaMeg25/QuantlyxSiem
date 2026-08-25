"""
Tests for the extension surface. These are the ones that break when someone
adds a platform, so they are written to fail loudly and say why.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from django.test import TestCase

from connectors.base import Capability, ConnectorError, PamConnector
from connectors.contract import ConnectorContractTests, RecordedResponse
from connectors.generic import GenericRestConnector, SpecificationError, dig
from connectors.registry import (
    ConnectorNotRegistered,
    catalogue,
    get_connector_class,
    register_connector,
    register_specification_vendor,
    registry,
    resolve_credentials,
    vendor_choices,
)

FIXTURES = Path(__file__).parent / "fixtures"

ACME_SPEC = {
    "auth": {
        "style": "token_post",
        "path": "/api/v2/session",
        "body": {"user": "{username}", "secret": "{password}"},
        "token_path": "data.sessionToken",
        "header_format": "Bearer {token}",
    },
    "accounts": {
        "path": "/api/v2/accounts",
        "items_path": "data.items",
        "pagination": {
            "style": "offset",
            "limit_parameter": "limit",
            "offset_parameter": "offset",
            "total_path": "data.total",
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
            "verification_ok": {"path": "lastCheck.result", "equals": "OK"},
        },
    },
    "activity": {
        "path": "/api/v2/audit",
        "items_path": "data.events",
        "since_parameter": "from",
        "field_map": {
            "external_id": "eventId",
            "account_external_id": "accountId",
            "action": "eventType",
            "occurred_at": {"path": "timestamp", "transform": "iso_datetime"},
            "actor": "principal",
            "ticket_reference": "changeTicket",
        },
    },
    "capabilities": ["accounts", "activity", "rotation_interval", "ownership", "verification"],
}


def acme_page(offset: int, total: int, size: int) -> dict:
    items = []
    for index in range(offset, min(offset + size, total)):
        items.append(
            {
                "accountId": f"acct-{index}",
                "loginName": f"svc_batch{index:03d}",
                "vaultName": "RPA-BATCH",
                "host": {"fqdn": f"host{index % 4}.corp"},
                "owner": {"email": f"owner{index % 3}@example.com"},
                "rotation": {
                    "lastChanged": 1_750_000_000_000 + index * 1000,
                    "everyDays": 30,
                    "managed": index % 5 != 0,
                },
                "state": "ENABLED",
                "lastCheck": {"result": "OK"},
                "password": "should-never-be-persisted",
            }
        )
    return {"data": {"total": total, "items": items}}


class RegistryTests(TestCase):
    def test_shipped_connectors_are_discovered(self):
        vendors = set(registry())
        self.assertLessEqual({"cyberark", "delinea", "beyondtrust", "hashicorp_vault"}, vendors)

    def test_unknown_vendor_names_what_is_available(self):
        with self.assertRaises(ConnectorNotRegistered) as caught:
            get_connector_class("not_a_real_platform")
        self.assertIn("cyberark", str(caught.exception))

    def test_duplicate_vendor_key_is_refused(self):
        class Duplicate(PamConnector):
            vendor = "cyberark"

            def authenticate(self): ...
            def iter_accounts(self): return iter(())

        with self.assertRaises(ValueError):
            register_connector(Duplicate)

    def test_connector_without_a_vendor_key_is_refused(self):
        class Anonymous(PamConnector):
            def authenticate(self): ...
            def iter_accounts(self): return iter(())

        with self.assertRaises(ValueError):
            register_connector(Anonymous)

    def test_specification_vendor_registers_without_a_class(self):
        register_specification_vendor("acme_vault_test", "Acme Vault")
        self.assertIn("acme_vault_test", registry())
        self.assertIn(("acme_vault_test", "Acme Vault"), vendor_choices())
        entry = next(row for row in catalogue() if row["vendor"] == "acme_vault_test")
        self.assertTrue(entry["specification_driven"])

    def test_catalogue_reports_capabilities_for_every_connector(self):
        for entry in catalogue():
            self.assertIn(Capability.ACCOUNTS, entry["capabilities"])

    def test_credential_reference_rejects_an_unknown_scheme(self):
        with self.assertRaises(Exception):
            resolve_credentials("vault-inline:username=admin")


class DottedPathTests(TestCase):
    def test_reads_nested_values_and_list_indexes(self):
        payload = {"a": {"b": [{"c": 7}]}}
        self.assertEqual(dig(payload, "a.b.0.c"), 7)

    def test_missing_path_returns_none_rather_than_raising(self):
        self.assertIsNone(dig({"a": 1}, "a.b.c"))


class GenericConnectorTests(TestCase):
    def _connector(self, spec=None, credentials=None):
        return GenericRestConnector(
            base_url="https://acme.invalid",
            credentials=credentials or {"username": "reader", "password": "irrelevant"},
            options={"spec": spec or ACME_SPEC, "page_size": 10, "tls_verify": False},
        )

    def test_missing_specification_fails_at_construction(self):
        with self.assertRaises(SpecificationError):
            GenericRestConnector(base_url="https://x.invalid", credentials={}, options={})

    def test_unknown_target_field_is_rejected_with_the_valid_list(self):
        spec = json.loads(json.dumps(ACME_SPEC))
        spec["accounts"]["field_map"]["not_a_field"] = "x"
        with self.assertRaises(SpecificationError) as caught:
            self._connector(spec)
        self.assertIn("not_a_field", str(caught.exception))

    def test_specification_must_map_the_identifier(self):
        spec = json.loads(json.dumps(ACME_SPEC))
        spec["accounts"]["field_map"].pop("external_id")
        with self.assertRaises(SpecificationError):
            self._connector(spec)

    def test_unknown_capability_is_rejected(self):
        spec = json.loads(json.dumps(ACME_SPEC))
        spec["capabilities"] = ["accounts", "telepathy"]
        with self.assertRaises(SpecificationError):
            self._connector(spec).declared_capabilities()

    def test_credential_placeholder_that_does_not_exist_is_named(self):
        spec = json.loads(json.dumps(ACME_SPEC))
        spec["auth"]["body"] = {"user": "{not_supplied}"}
        connector = self._connector(spec)
        connector.session.post = mock.Mock(return_value=RecordedResponse({}))
        with self.assertRaises(SpecificationError) as caught:
            connector.authenticate()
        self.assertIn("not_supplied", str(caught.exception))

    def _wire(self, connector, total=25, size=10):
        connector.session.post = mock.Mock(
            return_value=RecordedResponse({"data": {"sessionToken": "abc123"}})
        )
        pages = []
        offset = 0
        while offset < total:
            pages.append(RecordedResponse(acme_page(offset, total, size)))
            offset += size
        pages.append(RecordedResponse({"data": {"total": total, "items": []}}))
        cycle = iter(pages)
        connector.session.get = mock.Mock(side_effect=lambda *a, **k: next(cycle))
        return connector

    def test_authentication_sets_the_header_from_the_token_path(self):
        connector = self._wire(self._connector())
        connector.authenticate()
        self.assertEqual(connector.session.headers["Authorization"], "Bearer abc123")

    def test_offset_pagination_returns_every_record(self):
        connector = self._wire(self._connector(), total=25, size=10)
        connector.authenticate()
        accounts = list(connector.iter_accounts())
        self.assertEqual(len(accounts), 25)
        self.assertEqual(len({account.external_id for account in accounts}), 25)

    def test_transforms_and_maps_produce_normalized_values(self):
        connector = self._wire(self._connector(), total=5, size=10)
        connector.authenticate()
        account = next(iter(connector.iter_accounts()))
        self.assertEqual(account.status, "active")
        self.assertEqual(account.rotation_interval_days, 30)
        self.assertTrue(account.verification_ok)
        self.assertIsInstance(account.last_rotation_at, datetime)
        self.assertIsNotNone(account.last_rotation_at.tzinfo)

    def test_next_rotation_due_is_derived_when_the_platform_omits_it(self):
        connector = self._wire(self._connector(), total=3, size=10)
        connector.authenticate()
        account = next(iter(connector.iter_accounts()))
        self.assertEqual(
            account.next_rotation_due, account.last_rotation_at + timedelta(days=30)
        )

    def test_classification_runs_when_the_specification_does_not_map_kind(self):
        connector = self._wire(self._connector(), total=3, size=10)
        connector.authenticate()
        kinds = {account.kind for account in connector.iter_accounts()}
        self.assertEqual(kinds, {"service"})

    def test_credential_values_in_the_payload_are_scrubbed(self):
        connector = self._wire(self._connector(), total=3, size=10)
        connector.authenticate()
        for account in connector.iter_accounts():
            self.assertNotIn("should-never-be-persisted", json.dumps(account.raw))

    def test_activity_drops_events_before_the_boundary(self):
        connector = self._connector()
        connector.session.post = mock.Mock(
            return_value=RecordedResponse({"data": {"sessionToken": "abc123"}})
        )
        now = datetime.now(timezone.utc)
        payload = {
            "data": {
                "events": [
                    {
                        "eventId": "e1",
                        "accountId": "acct-1",
                        "eventType": "checkout",
                        "timestamp": now.isoformat(),
                        "principal": "operator@example.com",
                        "changeTicket": "CHG0001",
                    },
                    {
                        "eventId": "e2",
                        "accountId": "acct-1",
                        "eventType": "checkout",
                        "timestamp": (now - timedelta(days=30)).isoformat(),
                        "principal": "operator@example.com",
                    },
                ]
            }
        }
        connector.session.get = mock.Mock(return_value=RecordedResponse(payload))
        connector.authenticate()
        events = list(connector.iter_activity(now - timedelta(days=1)))
        self.assertEqual([event.external_id for event in events], ["e1"])
        self.assertEqual(events[0].ticket_reference, "CHG0001")

    def test_specification_pointing_at_a_credential_path_is_blocked(self):
        spec = json.loads(json.dumps(ACME_SPEC))
        spec["accounts"]["path"] = "/api/v2/accounts/1/credentials"
        connector = self._connector(spec)
        connector.session.headers["Authorization"] = "Bearer abc"
        with self.assertRaises(Exception):
            list(connector.iter_accounts())


class CapabilityGatingTests(TestCase):
    """A rule whose inputs a platform cannot supply must not run against it."""

    def setUp(self):
        from inventory.models import AccountKind, AccountStatus, ManagedAccount, PamSystem

        self.rich = PamSystem.objects.create(
            name="rich platform", vendor="cyberark", base_url="https://a.invalid",
            credential_reference="env:UNUSED", last_successful_collection=None,
            capabilities=[Capability.ACCOUNTS, Capability.USAGE_TIMESTAMPS, Capability.OWNERSHIP],
        )
        self.thin = PamSystem.objects.create(
            name="thin platform", vendor="hashicorp_vault", base_url="https://b.invalid",
            credential_reference="env:UNUSED", capabilities=[Capability.ACCOUNTS],
        )
        from django.utils import timezone

        for system in (self.rich, self.thin):
            ManagedAccount.objects.create(
                system=system, external_id="a1", username="svc_dormant",
                kind=AccountKind.SERVICE, status=AccountStatus.ACTIVE,
                owner_identity="", owner_team="",
                last_used_at=timezone.now() - timedelta(days=400),
                last_rotation_at=timezone.now(), rotation_interval_days=30,
                next_rotation_due=timezone.now() + timedelta(days=30),
                auto_rotation_enabled=True,
            )

    def test_dormancy_rule_only_runs_where_usage_timestamps_exist(self):
        from inventory.models import Finding
        from rules.engine import RuleEngine

        RuleEngine().run()
        systems = set(
            Finding.objects.filter(rule_id="USE-001").values_list("system__name", flat=True)
        )
        self.assertEqual(systems, {"rich platform"})

    def test_losing_a_capability_does_not_resolve_existing_findings(self):
        from inventory.models import Finding
        from rules.engine import RuleEngine

        RuleEngine().run()
        finding = Finding.objects.get(rule_id="USE-001", system=self.rich)
        self.rich.capabilities = [Capability.ACCOUNTS]
        self.rich.save()
        RuleEngine().run()
        finding.refresh_from_db()
        self.assertEqual(finding.state, Finding.State.OPEN)


class ShippedConnectorContractTests(TestCase):
    """Every registered connector must satisfy the structural parts of the contract."""

    def test_every_connector_declares_its_shape(self):
        for vendor, connector_class in registry().items():
            with self.subTest(vendor=vendor):
                self.assertTrue(connector_class.display_name, f"{vendor} needs a display_name")
                self.assertIn(Capability.ACCOUNTS, connector_class.capabilities)
                self.assertTrue(
                    set(connector_class.capabilities) <= set(Capability.ALL),
                    f"{vendor} declares a capability outside the vocabulary",
                )
                self.assertTrue(hasattr(connector_class, "iter_accounts"))
