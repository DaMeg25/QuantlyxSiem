"""
Answer "why am I not seeing any data".

Almost always the answer is that the shell that seeded and the shell running the
server are pointed at different databases -- USE_SQLITE set in one and not the
other, a different virtual environment, or a different working directory. This
prints exactly which database this process is talking to and what is in it, so
run it in the same shell as the server.
"""

from __future__ import annotations

import os
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import connection

from inventory.models import (
    CredentialAssetLink,
    Finding,
    LifecycleEvent,
    ManagedAccount,
    PamSystem,
    TargetAsset,
    TelemetrySource,
    UsageObservation,
)


class Command(BaseCommand):
    help = "Report which database this process uses and what is in it."

    def handle(self, *args, **options):
        database = settings.DATABASES["default"]
        engine = database["ENGINE"].rsplit(".", 1)[-1]
        name = str(database["NAME"])

        self.stdout.write(self.style.MIGRATE_HEADING("Environment"))
        self.stdout.write(f"  settings module   {os.environ.get('DJANGO_SETTINGS_MODULE', 'pamsiem.settings')}")
        self.stdout.write(f"  DJANGO_DEBUG      {os.environ.get('DJANGO_DEBUG', '(unset)')}")
        self.stdout.write(f"  USE_SQLITE        {os.environ.get('USE_SQLITE', '(unset)')}")
        self.stdout.write(f"  database engine   {engine}")
        self.stdout.write(f"  database          {name}")

        if engine == "sqlite3":
            path = Path(name)
            if path.exists():
                self.stdout.write(f"  file              exists, {path.stat().st_size // 1024} KiB")
            else:
                self.stdout.write(self.style.ERROR("  file              does not exist -- nothing has been written here"))
        else:
            self.stdout.write(f"  host              {database.get('HOST')}:{database.get('PORT')}")

        self.stdout.write(f"  cache backend     {settings.CACHES['default']['BACKEND'].rsplit('.', 1)[-1]}")
        self.stdout.write(f"  allowed hosts     {', '.join(settings.ALLOWED_HOSTS)}")
        if not settings.DEBUG:
            self.stdout.write(self.style.WARNING(
                "  DJANGO_DEBUG is not set, so Django will redirect http to https and "
                "runserver will appear dead."
            ))

        tables = set(connection.introspection.table_names())
        if "inventory_managedaccount" not in tables:
            self.stdout.write(self.style.ERROR(
                "\nThe schema is not present in this database. Run 'manage.py migrate' "
                "in this same shell, then 'manage.py seed_demo'."
            ))
            return

        counts = [
            ("platforms", PamSystem.objects.count()),
            ("managed accounts", ManagedAccount.objects.count()),
            ("lifecycle events", LifecycleEvent.objects.count()),
            ("findings", Finding.objects.count()),
            ("telemetry feeds", TelemetrySource.objects.count()),
            ("usage observations", UsageObservation.objects.count()),
            ("target assets", TargetAsset.objects.count()),
            ("credential-to-asset links", CredentialAssetLink.objects.count()),
        ]
        self.stdout.write(self.style.MIGRATE_HEADING("\nContents"))
        for label, count in counts:
            style = self.style.SUCCESS if count else self.style.WARNING
            self.stdout.write(f"  {label:<28} {style(str(count))}")

        from django.contrib.auth import get_user_model

        users = get_user_model().objects.count()
        self.stdout.write(f"  {'login accounts':<28} {(self.style.SUCCESS if users else self.style.ERROR)(str(users))}")

        self.stdout.write(self.style.MIGRATE_HEADING("\nNext step"))
        if not ManagedAccount.objects.exists():
            self.stdout.write("  Nothing is loaded. Run: python manage.py seed_demo")
        elif not Finding.objects.exists():
            self.stdout.write("  Accounts loaded but no findings. Run: python manage.py evaluate_rules")
        elif not users:
            self.stdout.write("  Data is present but there is no login. Run: python manage.py createsuperuser")
        else:
            self.stdout.write(self.style.SUCCESS(
                "  This database is populated. If the dashboard still looks empty, the server "
                "is running against a different one -- start it from this same shell, with the "
                "same environment variables."
            ))
        self.stdout.write("")
