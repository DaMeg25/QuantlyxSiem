"""Recompute every approval hash chain and report any that have been altered."""

from __future__ import annotations

from django.core.management.base import BaseCommand

from access.workflow import verify_all


class Command(BaseCommand):
    help = "Verify the tamper-evident approval records."

    def handle(self, *args, **options):
        result = verify_all()
        self.stdout.write(self.style.SUCCESS(f"{len(result['intact'])} approval chains intact"))
        for line in result["broken"]:
            self.stdout.write(self.style.ERROR(f"  ALTERED  {line}"))
        if result["broken"]:
            self.stdout.write(
                self.style.ERROR(
                    "\nApproval evidence for those requests cannot be relied on. This is an "
                    "incident, not a data quality issue: the records were changed after they "
                    "were written."
                )
            )
