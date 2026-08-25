"""
Bring up a complete working demonstration in one command.

This exists because the multi-step path has one failure mode that keeps
recurring and produces no error: seeding in one shell and starting the server in
another, with different environment variables, so the two point at different
databases. Everything looks like it worked and the dashboard is empty.

One command, one process, one database, and it prints the absolute path of the
database it used so there is nothing left to infer.

    python manage.py demo

Refuses to run outside a debug build against a non-SQLite database. Seeding
fabricates an estate and resets a login password; neither belongs anywhere near
a real deployment.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Migrate, seed, create a login, and verify. Local demonstration only."

    def add_arguments(self, parser):
        parser.add_argument("--accounts", type=int, default=1200)
        parser.add_argument("--username", default="demo")
        parser.add_argument("--password", default="", help="Generated and printed when omitted")
        parser.add_argument("--keep-data", action="store_true", help="Do not replace an existing estate")
        parser.add_argument("--force", action="store_true", help="Override the production guard")

    def handle(self, *args, **options):
        database = settings.DATABASES["default"]
        engine = database["ENGINE"].rsplit(".", 1)[-1]

        if not options["force"] and (engine != "sqlite3" or not settings.DEBUG):
            raise CommandError(
                "This command fabricates an estate and resets a login password, so it refuses "
                "to run outside a local build. Set DJANGO_DEBUG=true and USE_SQLITE=1, or pass "
                "--force if you are certain this database is disposable."
            )

        self.stdout.write(self.style.MIGRATE_HEADING("Database"))
        self.stdout.write(f"  {engine}  {database['NAME']}")

        self.stdout.write(self.style.MIGRATE_HEADING("\nApplying migrations"))
        call_command("migrate", verbosity=0)
        self.stdout.write("  done")

        from inventory.models import ManagedAccount

        existing = ManagedAccount.objects.count()
        if existing and options["keep_data"]:
            self.stdout.write(f"\nKeeping the existing estate of {existing} accounts")
        else:
            self.stdout.write(self.style.MIGRATE_HEADING("\nBuilding the estate"))
            call_command("seed_demo", accounts=options["accounts"], reset=bool(existing))

        user_model = get_user_model()
        password = options["password"] or secrets.token_urlsafe(12)
        user, created = user_model.objects.get_or_create(
            username=options["username"],
            defaults={"email": "sec.review@example.com", "is_staff": True, "is_superuser": True},
        )
        user.is_staff = user.is_superuser = True
        # The demonstration login doubles as an approver so the access queue has
        # something in it rather than looking broken.
        if not user.email:
            user.email = "sec.review@example.com"
        user.set_password(password)
        user.save()

        self.stdout.write(self.style.MIGRATE_HEADING("\nVerifying"))
        counts = self._counts()
        for label, count in counts:
            style = self.style.SUCCESS if count else self.style.ERROR
            self.stdout.write(f"  {label:<28} {style(str(count))}")

        if any(count == 0 for _, count in counts):
            raise CommandError(
                "Something did not load. Run 'python manage.py doctor' in this same shell."
            )

        self.stdout.write(self.style.MIGRATE_HEADING("\nStart the server from this same shell"))
        for name in ("DJANGO_SECRET_KEY", "DJANGO_DEBUG", "USE_SQLITE"):
            value = os.environ.get(name)
            if value:
                shown = "***" if name.endswith("KEY") else value
                self.stdout.write(f"  {name}={shown}")
        self.stdout.write("\n  python manage.py runserver\n")
        self.stdout.write(self.style.SUCCESS(f"  http://127.0.0.1:8000/   {options['username']} / {password}"))
        self.stdout.write(
            "\n  A different shell means different environment variables, which means a "
            "different\n  database and an empty dashboard. Start the server here.\n"
        )

    @staticmethod
    def _counts():
        from access.models import AccessGrant, AccessRequest, Resource
        from inventory.models import Finding, ManagedAccount, PamSystem, UsageObservation

        return [
            ("platforms", PamSystem.objects.count()),
            ("managed accounts", ManagedAccount.objects.count()),
            ("findings", Finding.objects.count()),
            ("usage observations", UsageObservation.objects.count()),
            ("resources", Resource.objects.count()),
            ("access grants", AccessGrant.objects.count()),
            ("access requests", AccessRequest.objects.count()),
        ]
