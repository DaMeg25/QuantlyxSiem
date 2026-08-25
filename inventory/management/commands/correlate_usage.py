"""Run the correlation pass on its own."""

from __future__ import annotations

from datetime import timedelta

from django.core.management.base import BaseCommand

from usage.correlate import correlate


class Command(BaseCommand):
    help = "Attribute observed logins to vault retrievals and rebuild credential reach."

    def add_arguments(self, parser):
        parser.add_argument("--window-hours", type=float, default=4.0)

    def handle(self, *args, **options):
        result = correlate(window=timedelta(hours=options["window_hours"]))
        self.stdout.write(
            f"matched {result['matched']} | unexplained {result['unexplained']} | "
            f"credential-to-asset links {result['asset_links']}"
        )
