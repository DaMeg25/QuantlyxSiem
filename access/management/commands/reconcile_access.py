"""
Enumerate a resource platform and reconcile it against approved access.

    python manage.py reconcile_access --platform github --organisation acme-bank
    python manage.py reconcile_access --platform gitlab --group platform

Read-only. The connectors cannot write to the platform, and paths returning
source or secrets are refused before the request is made.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from access.models import Resource
from access.reconcile import link_bot_credentials, reconcile_access, reconcile_resources
from connectors.registry import resolve_credentials
from resources.base import resource_registry


class Command(BaseCommand):
    help = "Pull resources and their access lists, then diff against approved grants."

    def add_arguments(self, parser):
        parser.add_argument("--platform", required=True)
        parser.add_argument("--base-url", default="")
        parser.add_argument("--credential-reference", default="")
        parser.add_argument("--organisation", default="")
        parser.add_argument("--group", default="")
        parser.add_argument("--limit", type=int, default=0, help="Cap resources, for a first run")

    def handle(self, *args, **options):
        registry = resource_registry()
        platform = options["platform"]
        if platform not in registry:
            raise CommandError(f"No resource connector for '{platform}'. Registered: {sorted(registry)}")

        reference = options["credential_reference"] or f"env:RESOURCE_{platform.upper()}"
        try:
            credentials = resolve_credentials(reference)
        except Exception as exc:
            raise CommandError(f"Could not resolve {reference}: {exc}") from exc

        defaults = {"github": "https://api.github.com", "gitlab": "https://gitlab.com"}
        base_url = options["base_url"] or defaults.get(platform, "")
        if not base_url:
            raise CommandError("Give --base-url for this platform")

        connector = registry[platform](
            base_url=base_url,
            credentials=credentials,
            options={"organisation": options["organisation"], "group": options["group"]},
        )

        with connector:
            summary = reconcile_resources(platform, connector.iter_resources())
            self.stdout.write(
                f"{summary['resources_seen']} resources seen, {summary['resources_created']} new"
            )

            resources = Resource.objects.filter(platform=platform, archived=False)
            if options["limit"]:
                resources = resources[: options["limit"]]

            totals = {"confirmed": 0, "discovered_unapproved": 0, "no_longer_present": 0}
            for resource in resources:
                try:
                    result = reconcile_access(resource, connector.iter_access(resource.identifier))
                except Exception as exc:  # noqa: BLE001
                    self.stdout.write(self.style.WARNING(f"  {resource.identifier}: {exc}"))
                    continue
                for key in totals:
                    totals[key] += result[key]

        linked = link_bot_credentials()
        self.stdout.write(
            f"\n{totals['confirmed']} grants confirmed, "
            f"{totals['no_longer_present']} no longer present, "
            f"{linked} bot identities linked to a vaulted credential"
        )
        if totals["discovered_unapproved"]:
            self.stdout.write(
                self.style.ERROR(
                    f"{totals['discovered_unapproved']} grants have no approved request behind them. "
                    "The access is real; the authority for it is not recorded. See ACC-001."
                )
            )
