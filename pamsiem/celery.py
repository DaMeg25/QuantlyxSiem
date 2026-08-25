from __future__ import annotations

import os

from celery import Celery
from celery.schedules import crontab

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "pamsiem.settings")

app = Celery("pamsiem")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()

app.conf.beat_schedule = {
    "collect-every-fifteen-minutes": {
        "task": "collection.collect_all",
        "schedule": crontab(minute="*/15"),
    },
    "correlate-usage-every-ten-minutes": {
        "task": "collection.correlate_usage",
        "schedule": crontab(minute="*/10"),
    },
    "evaluate-rules-hourly": {
        "task": "collection.evaluate_rules",
        "schedule": crontab(minute=5),
    },
    "export-every-five-minutes": {
        "task": "collection.export_pending",
        "schedule": crontab(minute="*/5"),
    },
    "prune-history-nightly": {
        "task": "collection.prune_history",
        "schedule": crontab(hour=2, minute=30),
    },
}
