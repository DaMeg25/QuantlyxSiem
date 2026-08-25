"""
Dry run a platform before enabling it.

Onboarding a new Privileged Access Management tool fails in predictable ways:
authentication works but pagination silently truncates, or the account list
comes back full while every lifecycle field is empty because the mapping points
at the wrong path. This command surfaces both without writing a single row.

    python manage.py validate_connector "Vault - corporate" --sample 25
"""

from __future__ import annotations

from collections import Counter

from django.core.management.base import BaseCommand, CommandError

from connectors.base import Capability, ConnectorError
from connectors.registry import build_connector
from inventory.models import PamSystem

LIFECYCLE_FIELDS = (
    "external_id", "username", "container", "target_address", "platform", "kind", "status",
    "owner_identity", "business_application", "last_rotation_at", "next_rotation_due",
    "rotation_interval_days", "auto_rotation_enabled", "verification_ok", "last_used_at",
    "exclusive_checkout", "entitled_identity_count",
)


class Command(BaseCommand):
    help = "Authenticate, pull a sample, and report field coverage. Writes nothing."

    def add_arguments(self, parser):
        parser.add_argument("platform", help="PamSystem name")
        parser.add_argument("--sample", type=int, default=25)
        parser.add_argument("--show", type=int, default=3, help="Accounts to print in full")

    def handle(self, *args, **options):
        try:
            system = PamSystem.objects.get(name=options["platform"])
        except PamSystem.DoesNotExist as exc:
            names = ", ".join(PamSystem.objects.values_list("name", flat=True)) or "none configured"
            raise CommandError(f"No platform named '{options['platform']}'. Known: {names}") from exc

        self.stdout.write(f"Platform  {system.name}  [{system.vendor}]  {system.base_url}")

        try:
            connector = build_connector(system)
        except Exception as exc:
            raise CommandError(f"Could not construct connector: {exc}") from exc

        capabilities = sorted(connector.declared_capabilities())
        self.stdout.write(f"Declares  {', '.join(capabilities)}")

        try:
            connector.authenticate()
            self.stdout.write(self.style.SUCCESS("Authentication succeeded"))
        except Exception as exc:
            raise CommandError(f"Authentication failed: {exc}") from exc

        filled = Counter()
        kinds = Counter()
        sample = []
        total = 0
        try:
            for account in connector.iter_accounts():
                total += 1
                kinds[account.kind] += 1
                for field in LIFECYCLE_FIELDS:
                    value = getattr(account, field, None)
                    if value not in (None, "", []):
                        filled[field] += 1
                if len(sample) < options["show"]:
                    sample.append(account)
                if total >= options["sample"]:
                    break
        except ConnectorError as exc:
            raise CommandError(f"Account collection failed after {total} records: {exc}") from exc
        finally:
            connector.close()

        if not total:
            raise CommandError("Authentication worked but no accounts were returned. Check scope and permissions.")

        self.stdout.write(f"\nSampled {total} accounts. Field coverage:")
        for field in LIFECYCLE_FIELDS:
            count = filled[field]
            share = count / total * 100
            bar = "#" * int(share / 5)
            style = self.style.SUCCESS if share > 80 else (self.style.WARNING if share else self.style.ERROR)
            self.stdout.write(f"  {field:<24} {style(f'{share:5.1f}%')} {bar}")

        self.stdout.write("\nClassification spread:")
        for kind, count in kinds.most_common():
            self.stdout.write(f"  {kind:<14} {count}")
        if kinds.get("unknown"):
            self.stdout.write(
                self.style.WARNING(
                    f"  {kinds['unknown']} unclassified. Every non-human rule is blind to these; "
                    "tune kind_patterns before enabling collection."
                )
            )

        empty = [field for field in ("last_rotation_at", "rotation_interval_days", "owner_identity") if not filled[field]]
        if empty:
            self.stdout.write(
                self.style.ERROR(
                    f"\nAlways empty: {', '.join(empty)}. Either the platform does not expose them "
                    "or the mapping points at the wrong path. Fix before enabling."
                )
            )

        if Capability.ACTIVITY in capabilities:
            self.stdout.write("\nActivity feed declared. Confirm events land after the first collection run.")

        for account in sample:
            self.stdout.write(f"\n  {account.username} @ {account.target_address or account.container}")
            self.stdout.write(f"    kind={account.kind} status={account.status} "
                              f"rotated={account.last_rotation_at} interval={account.rotation_interval_days} "
                              f"auto={account.auto_rotation_enabled} owner={account.owner_identity or '-'}")

        self.stdout.write(self.style.SUCCESS("\nDry run complete. Nothing was written."))
