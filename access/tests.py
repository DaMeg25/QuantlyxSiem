"""
Tests for the parts of access approval that a control test would probe.

Weighted heavily toward refusal. A workflow that approves correctly and also
lets a requester approve themselves has not implemented an approval control; it
has implemented a form.
"""

from __future__ import annotations

from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from access.models import (
    AccessGrant,
    AccessLevel,
    AccessRequest,
    ApprovalPolicy,
    ApprovalStep,
    Approver,
    Criticality,
    Principal,
    PrincipalType,
    Resource,
    ResourcePlatform,
)
from access.workflow import (
    SegregationOfDutiesError,
    WorkflowError,
    decide,
    hand_off,
    resolve_policy,
    submit,
    verify_chain,
)
from resources.base import NormalizedAccess, NormalizedResource, ResourceAccessBlocked


class Fixture(TestCase):
    def setUp(self):
        self.repository = Resource.objects.create(
            platform=ResourcePlatform.GITHUB,
            identifier="acme-bank/payments-core",
            production=True,
            criticality=Criticality.CRITICAL,
            owner_identity="owner@example.com",
            owner_team="Payments platform",
        )
        self.sandbox = Resource.objects.create(
            platform=ResourcePlatform.GITHUB,
            identifier="acme-bank/sandbox",
            production=False,
            criticality=Criticality.LOW,
        )
        self.developer = Principal.objects.create(
            identifier="r.chen", email="r.chen@example.com",
            principal_type=PrincipalType.DEVELOPER, team="Payments platform",
        )
        self.bot = Principal.objects.create(
            identifier="rpa-deploy[bot]", principal_type=PrincipalType.BOT,
        )
        self.policy = ApprovalPolicy.objects.create(
            name="Production repositories",
            platform=ResourcePlatform.GITHUB,
            applies_to_production_only=True,
            access_levels=[AccessLevel.WRITE, AccessLevel.ADMIN, AccessLevel.MAINTAIN],
            approvals_required=2,
            approver_groups=["repo-owners", "security"],
            maximum_duration_days=14,
            require_ticket_reference=True,
            require_justification=True,
        )
        ApprovalPolicy.objects.create(
            name="Everything else", approvals_required=1, maximum_duration_days=30,
            require_ticket_reference=False, require_justification=False,
        )
        self.owner = Approver.objects.create(
            identifier="owner@example.com", groups=["repo-owners"], team="Payments platform"
        )
        self.security = Approver.objects.create(
            identifier="sec@example.com", groups=["security"], team="Security", independent=True
        )

    def _request(self, **overrides):
        payload = dict(
            principal=self.developer,
            resource=self.repository,
            access_level=AccessLevel.WRITE,
            requested_by="lead@example.com",
            justification="Delivering the settlement retry work in CHG0044821",
            ticket_reference="CHG0044821",
            requested_days=7,
        )
        payload.update(overrides)
        return submit(**payload)


class PolicyResolutionTests(Fixture):
    def test_most_specific_policy_wins(self):
        policy = resolve_policy(self.repository, self.developer, AccessLevel.WRITE)
        self.assertEqual(policy.name, "Production repositories")

    def test_non_production_falls_through_to_the_general_policy(self):
        policy = resolve_policy(self.sandbox, self.developer, AccessLevel.WRITE)
        self.assertEqual(policy.name, "Everything else")

    def test_a_resource_specific_policy_beats_a_platform_one(self):
        specific = ApprovalPolicy.objects.create(
            name="This one repository", resource=self.repository,
            approvals_required=3, maximum_duration_days=3,
        )
        self.assertEqual(
            resolve_policy(self.repository, self.developer, AccessLevel.WRITE), specific
        )


class SubmissionTests(Fixture):
    def test_a_valid_request_lands_pending_with_the_policy_attached(self):
        request = self._request()
        self.assertEqual(request.state, AccessRequest.State.PENDING)
        self.assertEqual(request.approvals_required, 2)
        self.assertTrue(request.reference.startswith("ACR"))

    def test_a_duration_beyond_the_policy_ceiling_is_refused(self):
        with self.assertRaises(WorkflowError) as caught:
            self._request(requested_days=60)
        self.assertIn("14 day ceiling", str(caught.exception))

    def test_standing_access_is_refused_unless_the_policy_allows_it(self):
        with self.assertRaises(WorkflowError):
            self._request(requested_days=0)

    def test_missing_justification_is_refused_where_the_policy_requires_one(self):
        with self.assertRaises(WorkflowError):
            self._request(justification="   ")

    def test_missing_ticket_reference_is_refused(self):
        with self.assertRaises(WorkflowError):
            self._request(ticket_reference="")

    def test_a_bot_with_no_responsible_owner_cannot_hold_access(self):
        with self.assertRaises(WorkflowError) as caught:
            self._request(principal=self.bot)
        self.assertIn("responsible owner", str(caught.exception))

    def test_a_bot_with_an_owner_may_request(self):
        self.bot.responsible_owner = "a.iyer@example.com"
        self.bot.save()
        request = self._request(principal=self.bot)
        self.assertEqual(request.state, AccessRequest.State.PENDING)

    def test_archived_resources_cannot_be_requested(self):
        self.repository.archived = True
        self.repository.save()
        with self.assertRaises(WorkflowError):
            self._request()


class SegregationOfDutiesTests(Fixture):
    def test_the_requester_cannot_approve_their_own_request(self):
        request = self._request(requested_by="owner@example.com")
        with self.assertRaises(SegregationOfDutiesError):
            decide(request, approver_identity="owner@example.com",
                   decision=ApprovalStep.Decision.APPROVED)

    def test_a_person_cannot_approve_access_for_themselves(self):
        request = self._request()
        with self.assertRaises(SegregationOfDutiesError):
            decide(request, approver_identity="r.chen@example.com",
                   decision=ApprovalStep.Decision.APPROVED)

    def test_the_same_approver_cannot_count_twice(self):
        request = self._request()
        decide(request, approver_identity="owner@example.com",
               decision=ApprovalStep.Decision.APPROVED)
        with self.assertRaises(SegregationOfDutiesError):
            decide(request, approver_identity="owner@example.com",
                   decision=ApprovalStep.Decision.APPROVED)

    def test_an_approver_outside_the_entitled_groups_is_refused(self):
        Approver.objects.create(identifier="random@example.com", groups=["helpdesk"])
        request = self._request()
        with self.assertRaises(SegregationOfDutiesError):
            decide(request, approver_identity="random@example.com",
                   decision=ApprovalStep.Decision.APPROVED)

    def test_an_independent_approver_cannot_approve_for_their_own_team(self):
        self.security.team = "Payments platform"
        self.security.save()
        request = self._request()
        with self.assertRaises(SegregationOfDutiesError):
            decide(request, approver_identity="sec@example.com",
                   decision=ApprovalStep.Decision.APPROVED)


class DecisionTests(Fixture):
    def test_a_request_stays_pending_until_every_approval_is_recorded(self):
        request = self._request()
        decide(request, approver_identity="owner@example.com",
               decision=ApprovalStep.Decision.APPROVED)
        request.refresh_from_db()
        self.assertEqual(request.state, AccessRequest.State.PENDING)

        decide(request, approver_identity="sec@example.com",
               decision=ApprovalStep.Decision.APPROVED)
        request.refresh_from_db()
        self.assertEqual(request.state, AccessRequest.State.APPROVED)

    def test_one_rejection_ends_the_request(self):
        request = self._request()
        decide(request, approver_identity="owner@example.com",
               decision=ApprovalStep.Decision.REJECTED, comment="Use the pipeline identity")
        request.refresh_from_db()
        self.assertEqual(request.state, AccessRequest.State.REJECTED)

    def test_handoff_sets_the_expiry_and_does_not_create_a_grant(self):
        request = self._request()
        decide(request, approver_identity="owner@example.com", decision=ApprovalStep.Decision.APPROVED)
        decide(request, approver_identity="sec@example.com", decision=ApprovalStep.Decision.APPROVED)
        request.refresh_from_db()
        hand_off(request, system="ServiceNow", reference="RITM0099887")
        request.refresh_from_db()
        self.assertEqual(request.state, AccessRequest.State.PROVISIONED)
        self.assertIsNotNone(request.expires_at)
        # The grant appears only when the platform reports the access.
        self.assertEqual(AccessGrant.objects.count(), 0)

    def test_a_decision_cannot_be_recorded_on_a_closed_request(self):
        request = self._request()
        decide(request, approver_identity="owner@example.com", decision=ApprovalStep.Decision.REJECTED)
        request.refresh_from_db()
        with self.assertRaises(WorkflowError):
            decide(request, approver_identity="sec@example.com",
                   decision=ApprovalStep.Decision.APPROVED)


class TamperEvidenceTests(Fixture):
    def _approved(self):
        request = self._request()
        decide(request, approver_identity="owner@example.com", decision=ApprovalStep.Decision.APPROVED)
        decide(request, approver_identity="sec@example.com", decision=ApprovalStep.Decision.APPROVED)
        request.refresh_from_db()
        return request

    def test_an_untouched_chain_verifies(self):
        intact, message = verify_chain(self._approved())
        self.assertTrue(intact, message)

    def test_editing_a_decision_afterwards_is_detected(self):
        request = self._approved()
        step = request.approvals.first()
        step.comment = "actually I never approved this"
        step.save(update_fields=["comment"])
        intact, message = verify_chain(request)
        self.assertFalse(intact)
        self.assertIn("altered", message)

    def test_removing_a_step_breaks_the_chain(self):
        request = self._approved()
        request.approvals.filter(sequence=1).delete()
        intact, _ = verify_chain(request)
        self.assertFalse(intact)


class ReconciliationTests(Fixture):
    def _access(self, principal, level=AccessLevel.WRITE, **overrides):
        payload = dict(
            resource_identifier=self.repository.identifier,
            principal_identifier=principal,
            access_level=level,
        )
        payload.update(overrides)
        return NormalizedAccess(**payload)

    def test_access_with_no_request_behind_it_is_marked_discovered(self):
        from access.reconcile import reconcile_access

        result = reconcile_access(self.repository, [self._access("r.chen")])
        self.assertEqual(result["discovered_unapproved"], 1)
        grant = AccessGrant.objects.get()
        self.assertEqual(grant.origin, AccessGrant.Origin.DISCOVERED)

    def test_access_matching_an_approved_request_is_marked_governed(self):
        from access.reconcile import reconcile_access

        request = self._request()
        decide(request, approver_identity="owner@example.com", decision=ApprovalStep.Decision.APPROVED)
        decide(request, approver_identity="sec@example.com", decision=ApprovalStep.Decision.APPROVED)
        request.refresh_from_db()
        hand_off(request, system="ServiceNow", reference="RITM1")

        reconcile_access(self.repository, [self._access("r.chen")])
        grant = AccessGrant.objects.get()
        self.assertEqual(grant.origin, AccessGrant.Origin.APPROVED)
        self.assertIsNotNone(grant.expires_at)

    def test_access_no_longer_reported_is_marked_absent_not_deleted(self):
        from access.reconcile import reconcile_access

        reconcile_access(self.repository, [self._access("r.chen")])
        result = reconcile_access(self.repository, [])
        self.assertEqual(result["no_longer_present"], 1)
        grant = AccessGrant.objects.get()
        self.assertIsNotNone(grant.absent_since)
        self.assertFalse(grant.active)

    def test_a_machine_identity_is_classified_as_a_bot(self):
        from access.reconcile import reconcile_access

        reconcile_access(
            self.repository,
            [self._access("deploy-key:acme-bank/payments-core:9", machine_identity=True)],
        )
        principal = Principal.objects.get(identifier__startswith="deploy-key")
        self.assertEqual(principal.principal_type, PrincipalType.BOT)

    def test_expired_grants_still_present_are_reported(self):
        from access.reconcile import reconcile_access, stale_expiries

        reconcile_access(self.repository, [self._access("r.chen")])
        grant = AccessGrant.objects.get()
        grant.expires_at = timezone.now() - timedelta(days=5)
        grant.save()
        self.assertEqual([row.pk for row in stale_expiries()], [grant.pk])


class ResourceConnectorGuardTests(TestCase):
    def test_secret_and_source_paths_are_refused(self):
        from resources.github import GitHubConnector

        connector = GitHubConnector(
            base_url="https://api.github.invalid",
            credentials={"token": "unused"},
            options={"tls_verify": False},
        )
        for path in (
            "/repos/acme/app/actions/secrets",
            "/repos/acme/app/contents/README.md",
            "/repos/acme/app/dependabot/secrets",
        ):
            with self.subTest(path=path):
                with self.assertRaises(ResourceAccessBlocked):
                    connector._get(path)


class AccessRuleTests(Fixture):
    def _managed_account(self):
        from inventory.models import AccountKind, AccountStatus, ManagedAccount, PamSystem

        system = PamSystem.objects.create(
            name="vault", vendor="cyberark", base_url="https://x.invalid",
            credential_reference="env:UNUSED", capabilities=["accounts"],
            last_successful_collection=timezone.now(),
        )
        return ManagedAccount.objects.create(
            system=system, external_id="bot1", username="rpa-deploy",
            kind=AccountKind.SERVICE, status=AccountStatus.ACTIVE,
            last_rotation_at=timezone.now() - timedelta(days=400),
            rotation_interval_days=90,
            next_rotation_due=timezone.now() - timedelta(days=310),
            auto_rotation_enabled=False,
        )

    def test_unapproved_elevated_access_raises_a_finding(self):
        from access.reconcile import reconcile_access
        from inventory.models import Finding
        from rules.engine import RuleEngine

        self._managed_account()
        reconcile_access(self.repository, [
            NormalizedAccess(
                resource_identifier=self.repository.identifier,
                principal_identifier="r.chen",
                access_level=AccessLevel.ADMIN,
            )
        ])
        AccessGrant.objects.update(granted_at=timezone.now() - timedelta(days=30))
        RuleEngine().run()
        finding = Finding.objects.filter(rule_id="ACC-001").first()
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "critical")  # production resource

    def test_a_bot_writing_to_production_with_a_stale_credential_is_critical(self):
        from access.reconcile import reconcile_access
        from inventory.models import Finding
        from rules.engine import RuleEngine

        account = self._managed_account()
        self.bot.responsible_owner = "a.iyer@example.com"
        self.bot.managed_account = account
        self.bot.save()
        reconcile_access(self.repository, [
            NormalizedAccess(
                resource_identifier=self.repository.identifier,
                principal_identifier=self.bot.identifier,
                access_level=AccessLevel.WRITE,
                machine_identity=True,
            )
        ])
        RuleEngine().run()
        self.assertTrue(Finding.objects.filter(rule_id="ACC-006", account=account).exists())

    def test_expired_access_still_live_raises_the_closed_loop_finding(self):
        from access.reconcile import reconcile_access
        from inventory.models import Finding
        from rules.engine import RuleEngine

        self._managed_account()
        reconcile_access(self.repository, [
            NormalizedAccess(
                resource_identifier=self.repository.identifier,
                principal_identifier="r.chen",
                access_level=AccessLevel.WRITE,
            )
        ])
        AccessGrant.objects.update(expires_at=timezone.now() - timedelta(days=9))
        RuleEngine().run()
        self.assertTrue(Finding.objects.filter(rule_id="ACC-002").exists())

    def test_a_broken_approval_chain_raises_a_critical_finding(self):
        from inventory.models import Finding
        from rules.engine import RuleEngine

        self._managed_account()
        request = self._request()
        decide(request, approver_identity="owner@example.com", decision=ApprovalStep.Decision.APPROVED)
        decide(request, approver_identity="sec@example.com", decision=ApprovalStep.Decision.APPROVED)
        step = request.approvals.first()
        step.decision = ApprovalStep.Decision.APPROVED
        step.comment = "backdated"
        step.save(update_fields=["comment"])
        RuleEngine().run()
        self.assertTrue(Finding.objects.filter(rule_id="ACC-008").exists())


class WorkflowScreenTests(Fixture):
    """
    End-to-end through the screens, because the interesting failures are the
    ones where the form allows what the workflow forbids -- or worse, where a
    view forgets to ask the workflow at all.
    """

    def setUp(self):
        super().setUp()
        from django.contrib.auth.models import User

        self.requester = User.objects.create(username="lead", email="lead@example.com")
        self.owner_user = User.objects.create(username="owner", email="owner@example.com")
        self.security_user = User.objects.create(username="sec", email="sec@example.com")

    def _client(self, user):
        from django.test import Client

        client = Client()
        client.force_login(user)
        return client

    def _post_request(self, client, **overrides):
        payload = {
            "principal": self.developer.pk,
            "resource": self.repository.pk,
            "access_level": AccessLevel.WRITE,
            "requested_days": 7,
            "ticket_reference": "CHG0044821",
            "justification": "Settlement retry work, two week window",
        }
        payload.update(overrides)
        return client.post("/access/request/", payload, follow=True)

    def test_the_screens_require_a_login(self):
        from django.test import Client

        for url in ("/access/queue/", "/access/request/"):
            response = Client().get(url)
            self.assertIn(response.status_code, (302, 301), url)

    def test_a_valid_request_is_raised_through_the_form(self):
        response = self._post_request(self._client(self.requester))
        self.assertEqual(response.status_code, 200)
        request = AccessRequest.objects.get()
        self.assertEqual(request.state, AccessRequest.State.PENDING)
        self.assertEqual(request.requested_by, "lead@example.com")
        self.assertEqual(request.approvals_required, 2)

    def test_the_form_refuses_a_duration_beyond_the_ceiling(self):
        self._post_request(self._client(self.requester), requested_days=60)
        self.assertEqual(AccessRequest.objects.count(), 0)

    def test_the_form_refuses_a_bot_with_no_responsible_owner(self):
        self._post_request(self._client(self.requester), principal=self.bot.pk)
        self.assertEqual(AccessRequest.objects.count(), 0)

    def test_a_duplicate_open_request_is_refused(self):
        client = self._client(self.requester)
        self._post_request(client)
        self._post_request(client)
        self.assertEqual(AccessRequest.objects.count(), 1)

    def test_the_requester_cannot_approve_from_the_screen(self):
        self._post_request(self._client(self.requester))
        request = AccessRequest.objects.get()
        response = self._client(self.requester).post(
            f"/access/requests/{request.reference}/decide/",
            {"decision": ApprovalStep.Decision.APPROVED, "comment": "fine by me"},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        request.refresh_from_db()
        self.assertEqual(request.state, AccessRequest.State.PENDING)
        self.assertEqual(request.approvals.count(), 0)

    def test_the_queue_shows_the_reason_a_request_is_not_yours_to_decide(self):
        self._post_request(self._client(self.requester))
        response = self._client(self.requester).get("/access/queue/")
        body = response.content.decode()
        self.assertIn("cannot approve their own request", body)

    def test_two_approvals_move_it_to_approved_and_handoff_sets_the_expiry(self):
        self._post_request(self._client(self.requester))
        request = AccessRequest.objects.get()

        self._client(self.owner_user).post(
            f"/access/requests/{request.reference}/decide/",
            {"decision": ApprovalStep.Decision.APPROVED, "comment": "scope agreed"},
        )
        request.refresh_from_db()
        self.assertEqual(request.state, AccessRequest.State.PENDING)

        self._client(self.security_user).post(
            f"/access/requests/{request.reference}/decide/",
            {"decision": ApprovalStep.Decision.APPROVED, "comment": "time bounded"},
        )
        request.refresh_from_db()
        self.assertEqual(request.state, AccessRequest.State.APPROVED)

        self._client(self.owner_user).post(
            f"/access/requests/{request.reference}/handoff/",
            {"handoff_system": "ServiceNow", "handoff_reference": "RITM0099887"},
        )
        request.refresh_from_db()
        self.assertEqual(request.state, AccessRequest.State.PROVISIONED)
        self.assertIsNotNone(request.expires_at)
        self.assertEqual(AccessGrant.objects.count(), 0)

    def test_a_rejection_without_a_comment_is_refused(self):
        self._post_request(self._client(self.requester))
        request = AccessRequest.objects.get()
        self._client(self.owner_user).post(
            f"/access/requests/{request.reference}/decide/",
            {"decision": ApprovalStep.Decision.REJECTED, "comment": "  "},
        )
        request.refresh_from_db()
        self.assertEqual(request.state, AccessRequest.State.PENDING)

    def test_decisions_are_not_accepted_over_a_get(self):
        self._post_request(self._client(self.requester))
        request = AccessRequest.objects.get()
        response = self._client(self.owner_user).get(
            f"/access/requests/{request.reference}/decide/"
        )
        self.assertEqual(response.status_code, 405)
        self.assertEqual(request.approvals.count(), 0)

    def test_the_detail_screen_reports_a_broken_chain(self):
        self._post_request(self._client(self.requester))
        request = AccessRequest.objects.get()
        self._client(self.owner_user).post(
            f"/access/requests/{request.reference}/decide/",
            {"decision": ApprovalStep.Decision.APPROVED, "comment": "agreed"},
        )
        step = request.approvals.first()
        step.comment = "rewritten later"
        step.save(update_fields=["comment"])
        body = self._client(self.owner_user).get(
            f"/access/requests/{request.reference}/"
        ).content.decode()
        self.assertIn("ALTERED", body)

    def test_the_source_address_of_a_decision_is_recorded(self):
        self._post_request(self._client(self.requester))
        request = AccessRequest.objects.get()
        self._client(self.owner_user).post(
            f"/access/requests/{request.reference}/decide/",
            {"decision": ApprovalStep.Decision.APPROVED, "comment": "agreed"},
            REMOTE_ADDR="10.20.30.44",
        )
        self.assertEqual(request.approvals.first().source_address, "10.20.30.44")
