"""Collect from one platform now, without a worker. Writes inventory and events."""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from collection.tasks import collect_system
from inventory.models import PamSystem


class Command(BaseCommand):
    help = "Run a collection against one platform, or every enabled platform."

    def add_arguments(self, parser):
        parser.add_argument("platform", nargs="?", help="PamSystem name. Omit for all enabled.")
        parser.add_argument("--evaluate", action="store_true", help="Run the rules afterwards")

    def handle(self, *args, **options):
        if options["platform"]:
            systems = PamSystem.objects.filter(name=options["platform"])
            if not systems:
                raise CommandError(f"No platform named '{options['platform']}'")
        else:
            systems = PamSystem.objects.filter(enabled=True)

        for system in systems:
            self.stdout.write(f"Collecting {system.name} ...")
            try:
                # Called directly rather than through the broker.
                collect_system.run(system.pk)
            except Exception as exc:
                self.stdout.write(self.style.ERROR(f"  failed: {exc}"))
                continue
            run = system.runs.first()
            self.stdout.write(
                self.style.SUCCESS(
                    f"  {run.accounts_seen} accounts, {run.accounts_created} new, "
                    f"{run.accounts_retired} retired, {run.activities_ingested} events"
                )
            )

        if options["evaluate"]:
            from django.core.management import call_command

            call_command("evaluate_rules")
