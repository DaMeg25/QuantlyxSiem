"""Show the connector catalogue: what is registered and what each can supply."""

from __future__ import annotations

from django.core.management.base import BaseCommand

from connectors.base import Capability
from connectors.registry import catalogue
from inventory.models import PamSystem


class Command(BaseCommand):
    help = "List every registered connector, its capabilities, and where it is in use."

    def handle(self, *args, **options):
        in_use: dict[str, int] = {}
        for system in PamSystem.objects.all():
            in_use[system.vendor] = in_use.get(system.vendor, 0) + 1

        for entry in catalogue():
            count = in_use.get(entry["vendor"], 0)
            marker = self.style.SUCCESS("configured") if count else self.style.WARNING("not configured")
            kind = "specification driven" if entry["specification_driven"] else "purpose built"
            self.stdout.write(f"\n{entry['display_name']}  [{entry['vendor']}]  {marker}")
            self.stdout.write(f"  implementation   {entry['class_path']} ({kind})")
            self.stdout.write(f"  platforms using  {count}")
            missing = sorted(set(Capability.ALL) - set(entry["capabilities"]))
            self.stdout.write(f"  supplies         {', '.join(entry['capabilities'])}")
            if missing:
                self.stdout.write(f"  cannot supply    {', '.join(missing)}")
            if entry["required_credentials"]:
                self.stdout.write(f"  credential keys  {', '.join(entry['required_credentials'])}")
            if entry["documentation"]:
                self.stdout.write(f"  note             {entry['documentation']}")
        self.stdout.write("")
