"""
Ingest target-side authentication telemetry and correlate it against vault
retrievals.

    python manage.py ingest_usage --source "Cisco Identity Services Engine" --file /feeds/tacacs.log
    python manage.py ingest_usage --all          # every enabled source, from its ingest reference
    python manage.py correlate_usage             # correlation alone

The parser is chosen by the source's kind, so adding a feed is a configuration
change once a parser for that kind exists.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from django.utils import timezone

from django.core.management.base import BaseCommand, CommandError

from inventory.models import TelemetrySource, UsageObservation
from usage.correlate import correlate, record_observations
from usage.ingest import PARSERS


class Command(BaseCommand):
    help = "Load target authentication records, resolve them to accounts and assets, correlate."

    def add_arguments(self, parser):
        parser.add_argument("--source", help="TelemetrySource name")
        parser.add_argument("--file", help="Path to the exported records")
        parser.add_argument("--all", action="store_true", help="Every enabled source")
        parser.add_argument("--no-correlate", action="store_true")
        parser.add_argument(
            "--backfill-days", type=int, default=7,
            help="How far back to reach on a source's first pull",
        )

    def _pull(self, source, options) -> int:
        """Pull from a live feed and advance its cursor only on success."""
        from usage.collectors import CollectorError, build_collector

        try:
            collector = build_collector(source)
        except CollectorError as exc:
            self.stdout.write(self.style.ERROR(f"{source.name}: {exc}"))
            return 0

        since = source.last_ingest_at or timezone.now() - timedelta(
            days=int(options.get("backfill_days") or 7)
        )
        try:
            records = list(collector.collect(since))
        except Exception as exc:  # noqa: BLE001 -- the message is the useful part
            self.stdout.write(self.style.ERROR(f"{source.name}: collection failed: {exc}"))
            return 0

        written = record_observations(records, source=source)
        # Advanced only after the records are safely stored, so a failure
        # mid-pull re-reads rather than silently skipping a window.
        source.cursor = collector.next_cursor()
        source.save(update_fields=["cursor"])
        self.stdout.write(
            self.style.SUCCESS(
                f"{source.name}: pulled {len(records)} sessions since "
                f"{since:%Y-%m-%d %H:%M}, stored {written} new"
            )
        )
        commands = sum(record.get("command_count") or 0 for record in records)
        if commands:
            self.stdout.write(f"  {commands} commands recorded across those sessions")
        return written

    def handle(self, *args, **options):
        if options["all"]:
            sources = list(
                TelemetrySource.objects.filter(enabled=True).exclude(
                    ingest_reference="", collector=""
                )
            )
            if not sources:
                raise CommandError("No enabled sources with an ingest reference configured")
            jobs = [(source, source.ingest_reference) for source in sources]
        else:
            if not options["source"]:
                raise CommandError("Give --source, or --all")
            try:
                source = TelemetrySource.objects.get(name=options["source"])
            except TelemetrySource.DoesNotExist as exc:
                known = ", ".join(TelemetrySource.objects.values_list("name", flat=True)) or "none configured"
                raise CommandError(f"No telemetry source named '{options['source']}'. Known: {known}") from exc
            if not source.collector and not options["file"]:
                raise CommandError(
                    f"'{source.name}' has no collector configured, so it needs --file"
                )
            jobs = [(source, options["file"] or source.ingest_reference)]

        total = 0
        for source, location in jobs:
            # A source with a collector pulls for itself; one without waits for
            # files and parses them.
            if source.collector:
                total += self._pull(source, options)
                continue

            parser = PARSERS.get(source.kind)
            if parser is None:
                self.stdout.write(self.style.WARNING(f"{source.name}: no parser for kind '{source.kind}'"))
                continue
            path = Path(location)
            if not path.exists():
                self.stdout.write(self.style.ERROR(f"{source.name}: {path} not found"))
                continue

            records = list(parser(path))
            written = record_observations(records, source=source)
            total += written
            self.stdout.write(
                self.style.SUCCESS(
                    f"{source.name}: parsed {len(records)}, stored {written} new observations"
                )
            )

        unresolved = UsageObservation.objects.filter(
            correlation=UsageObservation.Correlation.UNMATCHED_ACCOUNT
        ).count()
        if unresolved:
            self.stdout.write(
                self.style.WARNING(
                    f"{unresolved} observations name an account that is not managed in any vault. "
                    "Those are privileged logins happening entirely outside the vaults."
                )
            )

        if not options["no_correlate"] and total:
            result = correlate()
            self.stdout.write(
                f"\nCorrelated: {result['matched']} logins matched to a retrieval, "
                f"{result['unexplained']} unexplained, {result['asset_links']} credential-to-asset links"
            )
            if result["unexplained"]:
                self.stdout.write(
                    self.style.ERROR(
                        "Unexplained logins mean a usable copy of those credentials exists "
                        "outside the vault. See USE-004."
                    )
                )
