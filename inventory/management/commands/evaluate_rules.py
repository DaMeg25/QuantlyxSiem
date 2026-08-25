"""Run the detection engine once, without a worker. Same code path as the task."""

from __future__ import annotations

from django.core.management.base import BaseCommand

from rules.engine import RuleEngine


class Command(BaseCommand):
    help = "Evaluate every rule against current inventory and reconcile findings."

    def add_arguments(self, parser):
        parser.add_argument("--platform", help="Limit to one PamSystem by name")

    def handle(self, *args, **options):
        system_id = None
        if options["platform"]:
            from inventory.models import PamSystem

            system_id = PamSystem.objects.get(name=options["platform"]).pk

        result = RuleEngine().run(system_id=system_id)
        self.stdout.write(
            f"opened {result['opened']} | still open {result['still_open']} | "
            f"resolved {result['resolved']} | rules unsupported on every platform "
            f"{result['unsupported_rules']}"
        )
        if result["unsupported_rules"]:
            self.stdout.write(
                self.style.WARNING("Check the Coverage page: those rules produce nothing anywhere.")
            )
