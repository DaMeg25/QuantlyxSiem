"""
Tests concentrate on the three places a defect would be expensive:
the metadata-only guards, the reconciliation diff, and the retire guard rail.
A wrong dashboard number is embarrassing; a leaked credential value or a
mass-retirement event storm is an incident.
"""

from __future__ import annotations

from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from collection.reconcile import reconcile_accounts
from connectors.base import (
    MetadataOnlySession,
    NormalizedAccount,
    SecretRetrievalBlocked,
    scrub,
)
from inventory.models import (
    AccountKind,
    AccountStatus,
    CollectionRun,
    Finding,
    LifecycleEvent,
    ManagedAccount,
    PamSystem,
)
from rules.engine import RuleEngine


class MetadataOnlyGuardTests(TestCase):
    BLOCKED = [
        "https://pvwa.example.com/PasswordVault/API/Accounts/12_3/Password/Retrieve",
        "https://ss.example.com/api/v1/secrets/44/fields/password",
        "https://vault.example.com/v1/database/static-creds/payments",
        "https://ps.example.com/BeyondTrust/api/public/v3/ManagedAccounts/9/Credentials",
    ]

    def test_credential_endpoints_are_refused(self):
        session = MetadataOnlySession()
        for url in self.BLOCKED:
            with self.subTest(url=url):
                with self.assertRaises(SecretRetrievalBlocked):
                    session.get(url, timeout=1)

    def test_scrub_removes_values_at_any_depth(self):
        payload = {
            "userName": "svc_batch",
            "password": "hunter2",
            "nested": [{"clientSecret": "abc", "host": "h1"}],
        }
        cleaned = scrub(payload)
        self.assertEqual(cleaned["userName"], "svc_batch")
        self.assertNotIn("hunter2", str(cleaned))
        self.assertNotIn("abc", str(cleaned))

    def test_normalized_account_scrubs_on_construction(self):
        account = NormalizedAccount(external_id="1", username="a", raw={"password": "x"})
        self.assertNotEqual(account.raw["password"], "x")


class ReconciliationTests(TestCase):
    def setUp(self):
        self.system = PamSystem.objects.create(
            name="test vault", vendor="cyberark",
            base_url="https://example.com", credential_reference="env:UNUSED",
        )
        self.run = CollectionRun.objects.create(system=self.system)

    def _account(self, **overrides) -> NormalizedAccount:
        base = dict(
            external_id="acct-1",
            username="svc_payments",
            container="RPA-BATCH",
            kind=AccountKind.SERVICE,
            status=AccountStatus.ACTIVE,
            auto_rotation_enabled=True,
            last_rotation_at=timezone.now() - timedelta(days=10),
            rotation_interval_days=30,
        )
        base.update(overrides)
        return NormalizedAccount(**base)

    def test_first_pull_creates_account_and_onboarding_event(self):
        reconcile_accounts(self.system, self.run, [self._account()])
        self.assertEqual(ManagedAccount.objects.count(), 1)
        self.assertTrue(
            LifecycleEvent.objects.filter(kind=LifecycleEvent.Kind.ONBOARDED).exists()
        )

    def test_disabling_automatic_rotation_emits_an_event(self):
        reconcile_accounts(self.system, self.run, [self._account()])
        second_run = CollectionRun.objects.create(system=self.system)
        reconcile_accounts(self.system, second_run, [self._account(auto_rotation_enabled=False)])
        self.assertTrue(
            LifecycleEvent.objects.filter(
                kind=LifecycleEvent.Kind.AUTO_ROTATION_DISABLED
            ).exists()
        )

    def test_new_rotation_timestamp_emits_a_rotation_event(self):
        reconcile_accounts(self.system, self.run, [self._account()])
        second_run = CollectionRun.objects.create(system=self.system)
        reconcile_accounts(
            self.system, second_run, [self._account(last_rotation_at=timezone.now())]
        )
        self.assertEqual(
            LifecycleEvent.objects.filter(kind=LifecycleEvent.Kind.ROTATED).count(), 1
        )

    def test_missing_account_is_retired(self):
        accounts = [self._account(external_id=f"acct-{index}") for index in range(10)]
        reconcile_accounts(self.system, self.run, accounts)
        second_run = CollectionRun.objects.create(system=self.system)
        reconcile_accounts(self.system, second_run, accounts[:9])
        self.assertEqual(
            ManagedAccount.objects.filter(status=AccountStatus.DELETED).count(), 1
        )

    def test_truncated_pull_does_not_mass_retire(self):
        """A vendor outage returning a short page must not look like a purge."""
        accounts = [self._account(external_id=f"acct-{index}") for index in range(10)]
        reconcile_accounts(self.system, self.run, accounts)
        second_run = CollectionRun.objects.create(system=self.system)
        reconcile_accounts(self.system, second_run, accounts[:2])
        self.assertEqual(
            ManagedAccount.objects.filter(status=AccountStatus.DELETED).count(), 0
        )


class RuleTests(TestCase):
    def setUp(self):
        self.system = PamSystem.objects.create(
            name="test vault", vendor="delinea",
            base_url="https://example.com", credential_reference="env:UNUSED",
            last_successful_collection=timezone.now(),
        )

    def _make(self, **overrides) -> ManagedAccount:
        defaults = dict(
            system=self.system,
            external_id="a1",
            username="svc_batch",
            kind=AccountKind.SERVICE,
            status=AccountStatus.ACTIVE,
            owner_identity="owner@example.com",
            rotation_interval_days=30,
            last_rotation_at=timezone.now() - timedelta(days=5),
            auto_rotation_enabled=True,
            last_used_at=timezone.now(),
        )
        defaults.update(overrides)
        defaults["next_rotation_due"] = defaults["last_rotation_at"] + timedelta(
            days=defaults["rotation_interval_days"]
        ) if defaults["last_rotation_at"] else None
        return ManagedAccount.objects.create(**defaults)

    def test_overdue_rotation_opens_one_finding(self):
        self._make(last_rotation_at=timezone.now() - timedelta(days=200))
        RuleEngine().run()
        self.assertEqual(Finding.objects.filter(rule_id="ROT-001").count(), 1)

    def test_repeat_evaluation_does_not_duplicate_findings(self):
        self._make(last_rotation_at=timezone.now() - timedelta(days=200))
        RuleEngine().run()
        RuleEngine().run()
        self.assertEqual(Finding.objects.filter(rule_id="ROT-001").count(), 1)

    def test_clearing_the_condition_resolves_the_finding(self):
        account = self._make(last_rotation_at=timezone.now() - timedelta(days=200))
        RuleEngine().run()
        account.last_rotation_at = timezone.now()
        account.next_rotation_due = timezone.now() + timedelta(days=30)
        account.save()
        RuleEngine().run()
        finding = Finding.objects.get(rule_id="ROT-001")
        self.assertEqual(finding.state, Finding.State.RESOLVED)
        self.assertIsNotNone(finding.resolved_at)

    def test_non_human_with_rotation_disabled_is_flagged(self):
        self._make(kind=AccountKind.BOT, auto_rotation_enabled=False)
        RuleEngine().run()
        self.assertTrue(Finding.objects.filter(rule_id="BOT-001").exists())

    def test_human_account_with_rotation_disabled_is_not_flagged_by_bot_rule(self):
        self._make(kind=AccountKind.HUMAN, auto_rotation_enabled=False)
        RuleEngine().run()
        self.assertFalse(Finding.objects.filter(rule_id="BOT-001").exists())

    def test_stale_collection_is_itself_a_finding(self):
        self._make()
        self.system.last_successful_collection = timezone.now() - timedelta(days=3)
        self.system.save()
        RuleEngine().run()
        self.assertTrue(Finding.objects.filter(rule_id="OPS-001").exists())


class UsageCorrelationTests(TestCase):
    """
    The correlation pass decides whether a privileged login is accounted for.
    A false match hides the finding that matters most, so these test the
    attribution rules rather than the happy path.
    """

    def setUp(self):
        from inventory.models import TelemetrySource

        self.system = PamSystem.objects.create(
            name="test vault", vendor="cyberark", base_url="https://example.com",
            credential_reference="env:UNUSED", capabilities=["accounts", "activity"],
            last_successful_collection=timezone.now(),
        )
        self.account = ManagedAccount.objects.create(
            system=self.system, external_id="a1", username="svc_batch",
            kind=AccountKind.SERVICE, status=AccountStatus.ACTIVE,
            target_address="core-rtr-01", last_rotation_at=timezone.now(),
            rotation_interval_days=30, next_rotation_due=timezone.now() + timedelta(days=30),
        )
        self.source = TelemetrySource.objects.create(
            name="test feed", kind=TelemetrySource.Kind.NETWORK_AAA, last_ingest_at=timezone.now()
        )
        self.now = timezone.now()

    def _login(self, when, *, asset="core-rtr-01", name="svc_batch", actor="", key=None):
        from usage.correlate import record_observations
        from inventory.models import UsageObservation

        record_observations([{
            "observed_account_name": name,
            "asset_identifier": asset,
            "occurred_at": when,
            "mechanism": UsageObservation.Mechanism.TARGET_AUTHENTICATION,
            "actor": actor,
            "dedupe_key": key or f"test-{name}-{asset}-{when.timestamp()}",
        }], source=self.source)

    def _retrieval(self, when, actor="", key="r1"):
        return LifecycleEvent.objects.create(
            account=self.account, kind=LifecycleEvent.Kind.CHECKED_OUT,
            occurred_at=when, actor=actor, dedupe_key=key,
        )

    def test_login_after_a_retrieval_is_matched(self):
        from usage.correlate import correlate
        from inventory.models import UsageObservation

        self._retrieval(self.now - timedelta(minutes=30))
        self._login(self.now - timedelta(minutes=20))
        correlate()
        observation = UsageObservation.objects.get()
        self.assertEqual(observation.correlation, UsageObservation.Correlation.MATCHED)
        self.assertAlmostEqual(observation.correlation_lag_seconds, 600, delta=5)

    def test_login_with_no_retrieval_is_unexplained(self):
        from usage.correlate import correlate
        from inventory.models import UsageObservation

        self._login(self.now - timedelta(minutes=20))
        correlate()
        self.assertEqual(
            UsageObservation.objects.get().correlation, UsageObservation.Correlation.UNEXPLAINED
        )

    def test_one_retrieval_cannot_explain_two_logins(self):
        """Otherwise a single checkout launders an unlimited number of logins."""
        from usage.correlate import correlate
        from inventory.models import UsageObservation

        self._retrieval(self.now - timedelta(hours=1))
        self._login(self.now - timedelta(minutes=50), key="one")
        self._login(self.now - timedelta(minutes=40), key="two")
        correlate()
        states = sorted(UsageObservation.objects.values_list("correlation", flat=True))
        self.assertEqual(states, ["matched", "unexplained"])

    def test_a_retrieval_outside_the_window_does_not_match(self):
        from usage.correlate import correlate
        from inventory.models import UsageObservation

        self._retrieval(self.now - timedelta(days=2))
        self._login(self.now - timedelta(minutes=5))
        correlate()
        self.assertEqual(
            UsageObservation.objects.get().correlation, UsageObservation.Correlation.UNEXPLAINED
        )

    def test_a_different_person_does_not_inherit_the_retrieval(self):
        from usage.correlate import correlate
        from inventory.models import UsageObservation

        self._retrieval(self.now - timedelta(minutes=30), actor="alice@example.com")
        self._login(self.now - timedelta(minutes=20), actor="bob@example.com")
        correlate()
        self.assertEqual(
            UsageObservation.objects.get().correlation, UsageObservation.Correlation.UNEXPLAINED
        )

    def test_account_names_are_normalized_across_targets(self):
        from usage.correlate import correlate
        from inventory.models import UsageObservation

        self._retrieval(self.now - timedelta(minutes=30))
        self._login(self.now - timedelta(minutes=20), name="CORP\\svc_batch")
        correlate()
        observation = UsageObservation.objects.get()
        self.assertEqual(observation.account, self.account)
        self.assertEqual(observation.correlation, UsageObservation.Correlation.MATCHED)

    def test_a_login_by_an_unmanaged_account_is_flagged_not_dropped(self):
        from usage.correlate import correlate
        from inventory.models import UsageObservation

        self._login(self.now, name="local_admin")
        correlate()
        self.assertEqual(
            UsageObservation.objects.get().correlation,
            UsageObservation.Correlation.UNMATCHED_ACCOUNT,
        )

    def test_reach_records_assets_outside_the_mapped_target(self):
        from usage.correlate import correlate
        from inventory.models import CredentialAssetLink

        self._login(self.now, asset="core-rtr-01", key="in-scope")
        self._login(self.now, asset="oradb-prod-03", key="off-scope")
        correlate()
        off = CredentialAssetLink.objects.get(asset__identifier="oradb-prod-03")
        self.assertTrue(off.outside_mapped_scope)
        self.assertFalse(CredentialAssetLink.objects.get(asset__identifier="core-rtr-01").outside_mapped_scope)

    def test_unexplained_logins_raise_the_critical_finding(self):
        from usage.correlate import correlate
        from rules.engine import RuleEngine

        self._login(self.now - timedelta(hours=2))
        correlate()
        RuleEngine().run()
        self.assertTrue(Finding.objects.filter(rule_id="USE-004", account=self.account).exists())

    def test_usage_rules_are_inert_with_no_telemetry_feed(self):
        """Without a feed the rule must not run, rather than reporting nothing found."""
        from inventory.models import TelemetrySource
        from rules.engine import RuleEngine

        TelemetrySource.objects.all().delete()
        RuleEngine().run()
        self.assertFalse(Finding.objects.filter(rule_id="USE-004").exists())


class TelemetryParserTests(TestCase):
    def test_tacacs_accounting_rolls_commands_into_one_session(self):
        import tempfile

        from usage.ingest import parse_tacacs_accounting

        lines = "\n".join(
            f'Timestamp="2026-08-10 09:1{n}:00" NetworkDeviceName=core-rtr-01 UserName=adm_net '
            f'AcctSessionId=S123 Privilege-Level=15 CmdSet="show run"' for n in range(3)
        )
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as handle:
            handle.write(lines)
            path = handle.name
        records = list(parse_tacacs_accounting(path))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["command_count"], 3)
        self.assertEqual(records[0]["asset_identifier"], "core-rtr-01")
        self.assertIsNotNone(records[0]["occurred_at"].tzinfo)

    def test_windows_parser_drops_machine_and_service_logons(self):
        import json
        import tempfile

        from usage.ingest import parse_windows_security

        rows = [
            {"EventID": "4624", "TargetUserName": "adm_win", "Computer": "nyc-dc01.corp",
             "LogonType": "10", "TimeCreated": "2026-08-10T09:00:00Z", "IpAddress": "10.1.1.1"},
            {"EventID": "4624", "TargetUserName": "NYC-DC01$", "Computer": "nyc-dc01.corp",
             "LogonType": "3", "TimeCreated": "2026-08-10T09:00:00Z"},
            {"EventID": "4624", "TargetUserName": "svc_x", "Computer": "nyc-dc01.corp",
             "LogonType": "5", "TimeCreated": "2026-08-10T09:00:00Z"},
        ]
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as handle:
            handle.write("\n".join(json.dumps(row) for row in rows))
            path = handle.name
        records = list(parse_windows_security(path))
        self.assertEqual([record["observed_account_name"] for record in records], ["adm_win"])


class TacacsCollectorTests(TestCase):
    """
    The syslog collector reads a moving target: files rotate, pulls resume, and
    a mistake either loses records silently or replays them. Both are worse than
    an error, so these test the cursor rather than the parsing.
    """

    def setUp(self):
        import tempfile

        from inventory.models import TelemetrySource

        self.directory = tempfile.mkdtemp()
        self.source = TelemetrySource.objects.create(
            name="Identity Services Engine syslog",
            kind=TelemetrySource.Kind.NETWORK_AAA,
            collector="syslog_spool",
            settings={"path_glob": f"{self.directory}/*.log"},
        )
        self.since = timezone.now() - timedelta(days=1)

    def _write(self, filename, lines, mode="a"):
        import os

        with open(os.path.join(self.directory, filename), mode) as handle:
            handle.write("\n".join(lines) + "\n")

    def _line(self, minute, command="show running-config", user="adm_net", device="core-rtr-01"):
        stamp = (timezone.now() - timedelta(minutes=minute)).strftime("%Y-%m-%d %H:%M:%S")
        return (
            f'Timestamp="{stamp}" NetworkDeviceName={device} UserName={user} '
            f'AcctSessionId=S{minute} Privilege-Level=15 CmdSet="{command}"'
        )

    def _collect(self):
        from usage.collectors import build_collector

        collector = build_collector(self.source)
        records = list(collector.collect(self.since))
        self.source.cursor = collector.next_cursor()
        self.source.save(update_fields=["cursor"])
        return records

    def test_commands_roll_up_into_one_session(self):
        self._write("acct.log", [self._line(10, "show run"), self._line(10, "configure terminal")])
        records = self._collect()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["command_count"], 2)
        self.assertEqual(records[0]["privilege_level"], "15")
        self.assertEqual(records[0]["asset_identifier"], "core-rtr-01")

    def test_a_second_pull_does_not_replay_what_it_already_read(self):
        self._write("acct.log", [self._line(20)])
        self.assertEqual(len(self._collect()), 1)
        self.assertEqual(len(self._collect()), 0)

    def test_a_second_pull_picks_up_new_lines_only(self):
        self._write("acct.log", [self._line(30)])
        self._collect()
        self._write("acct.log", [self._line(5, user="adm_other")])
        records = self._collect()
        self.assertEqual([record["observed_account_name"] for record in records], ["adm_other"])

    def test_rotation_is_detected_rather_than_skipped(self):
        """A truncated file must be re-read from the start, not seeked past its end."""
        self._write("acct.log", [self._line(40), self._line(41)])
        self._collect()
        self._write("acct.log", [self._line(2, user="after_rotation")], mode="w")
        records = self._collect()
        self.assertEqual([record["observed_account_name"] for record in records], ["after_rotation"])

    def test_records_older_than_the_window_are_dropped(self):
        self._write("acct.log", [self._line(60 * 24 * 3)])
        self.assertEqual(len(self._collect()), 0)

    def test_collector_registry_reports_what_is_available(self):
        from usage.collectors import collector_choices, collector_registry

        self.assertIn("ise_data_connect", collector_registry())
        self.assertIn("syslog_spool", collector_registry())
        self.assertIn(("", "Delivered as files (parsed from the ingest reference)"), collector_choices())

    def test_missing_required_settings_fail_at_construction(self):
        from inventory.models import TelemetrySource
        from usage.collectors import CollectorError, build_collector

        broken = TelemetrySource.objects.create(
            name="misconfigured", kind=TelemetrySource.Kind.NETWORK_AAA,
            collector="tacplus_log", settings={},
        )
        with self.assertRaises(CollectorError):
            build_collector(broken)

    def test_tacacs_usage_reaches_the_correlation_pass(self):
        from usage.correlate import correlate
        from inventory.models import ManagedAccount, PamSystem, UsageObservation
        from usage.correlate import record_observations

        system = PamSystem.objects.create(
            name="vault", vendor="cyberark", base_url="https://x.invalid",
            credential_reference="env:UNUSED", capabilities=["accounts"],
        )
        ManagedAccount.objects.create(
            system=system, external_id="a1", username="adm_net",
            kind=AccountKind.HUMAN, status=AccountStatus.ACTIVE,
            target_address="core-rtr-01",
        )
        self._write("acct.log", [self._line(15)])
        record_observations(self._collect(), source=self.source)
        correlate()
        observation = UsageObservation.objects.get()
        self.assertEqual(observation.account.username, "adm_net")
        self.assertEqual(observation.correlation, UsageObservation.Correlation.UNEXPLAINED)
