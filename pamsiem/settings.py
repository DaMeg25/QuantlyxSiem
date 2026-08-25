"""Django settings. Everything environment-specific comes from the environment."""

from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def env_bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def env_list(name: str, default: str = "") -> list[str]:
    return [item.strip() for item in os.environ.get(name, default).split(",") if item.strip()]


SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "")
if not SECRET_KEY:
    raise RuntimeError("DJANGO_SECRET_KEY must be set")

DEBUG = env_bool("DJANGO_DEBUG", False)
ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS")
if not ALLOWED_HOSTS:
    # In a local build, accept whatever hostname the browser used. A restrictive
    # default here returns a bare 400 when someone reaches the server by machine
    # name or address, which is indistinguishable from the application being
    # broken. Production must set DJANGO_ALLOWED_HOSTS explicitly, and the check
    # below refuses to start without it.
    if DEBUG:
        ALLOWED_HOSTS = ["*"]
    else:
        raise RuntimeError(
            "DJANGO_ALLOWED_HOSTS must list the hostnames this service answers on"
        )
CSRF_TRUSTED_ORIGINS = env_list("DJANGO_CSRF_TRUSTED_ORIGINS")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "django_filters",
    "inventory",
    "access",
    "collection",
    "rules",
    "dashboard",
    "api",
    "export",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "pamsiem.urls"
WSGI_APPLICATION = "pamsiem.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "dashboard" / "templates", BASE_DIR / "access" / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ]
        },
    }
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("DATABASE_NAME", "pamsiem"),
        "USER": os.environ.get("DATABASE_USER", "pamsiem"),
        "PASSWORD": os.environ.get("DATABASE_PASSWORD", ""),
        "HOST": os.environ.get("DATABASE_HOST", "localhost"),
        "PORT": os.environ.get("DATABASE_PORT", "5432"),
        "CONN_MAX_AGE": 60,
        "OPTIONS": {"sslmode": os.environ.get("DATABASE_SSLMODE", "require")},
    }
}
if env_bool("USE_SQLITE"):  # local development only
    DATABASES["default"] = {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "development.sqlite3",
    }

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
     "OPTIONS": {"min_length": 14}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = os.environ.get("DISPLAY_TIME_ZONE", "America/New_York")
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "/admin/login/"
LOGIN_REDIRECT_URL = "/"

# Transport hardening. The dashboard shows which privileged accounts exist and
# where they are weak, which is a reconnaissance map. Treat it as production
# security infrastructure, not an internal reporting tool.
SECURE_SSL_REDIRECT = env_bool("SECURE_SSL_REDIRECT", not DEBUG)
SECURE_HSTS_SECONDS = 31536000 if not DEBUG else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_AGE = 3600
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
        "rest_framework.authentication.TokenAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_FILTER_BACKENDS": ["django_filters.rest_framework.DjangoFilterBackend"],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.LimitOffsetPagination",
    "PAGE_SIZE": 100,
    "DEFAULT_THROTTLE_RATES": {"user": "600/hour"},
}

CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", CELERY_BROKER_URL)
CELERY_TASK_ACKS_LATE = True
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_TASK_TIME_LIMIT = 3600
CELERY_BROKER_USE_SSL = env_bool("CELERY_BROKER_USE_SSL", False) or None

# Connector defaults, merged under each PamSystem's own options.
PAM_CONNECTOR_DEFAULTS = {
    "tls_verify": os.environ.get("PAM_CA_BUNDLE", True),
    "page_size": 250,
    "timeout_seconds": 45,
    "default_rotation_interval_days": 90,
    # Deployment-specific classification. First match wins.
    "kind_patterns": [
        [r"(^|/)rpa[_-]", "bot"],
        [r"(^|/)svc[_-]", "service"],
        [r"break.?glass|firecall", "break_glass"],
        [r"vendor[_-]|contractor", "vendor"],
    ],
}

# Register a specification-driven platform without writing a connector class.
# The vendor key appears in the configuration screen; the implementation lives
# entirely in that platform's options["spec"]. See connectors/generic.py.
PAM_SPECIFICATION_VENDORS = {
    # "keeper_secrets_manager": "Keeper Secrets Manager",
    # "senhasegura": "Senhasegura",
    # Used by seed_demo to show a specification-driven platform on the coverage
    # matrix. Remove it before production; it points at nothing real.
    "acme_vault_demo": "Acme Vault (demonstration)",
}

# Rules that join against an external list -- OWN-002 checks owners against the
# active-worker feed under the key "active_identities" -- need a cache shared
# between the web process and the workers. The in-memory default is per process,
# so a value written by a task would be invisible to the dashboard.
if os.environ.get("REDIS_URL") or os.environ.get("CELERY_BROKER_URL"):
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": os.environ.get("REDIS_URL", os.environ.get("CELERY_BROKER_URL", "")),
        }
    }
else:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.filebased.FileBasedCache",
            "LOCATION": str(BASE_DIR / ".cache"),
        }
    }

# Snapshots are written when an account changes, plus one heartbeat per account
# per this interval. Lower it for a finer historical series at higher volume.
# Access approval. This system records decisions and hands provisioning to the
# system of record; it does not grant access itself. See access/README in the
# project README for why.
ACCESS_MAX_GRANT_DAYS = int(os.environ.get("ACCESS_MAX_GRANT_DAYS", "90"))
ACCESS_DEFAULT_GRANT_DAYS = int(os.environ.get("ACCESS_DEFAULT_GRANT_DAYS", "30"))

SNAPSHOT_MIN_INTERVAL_HOURS = float(os.environ.get("SNAPSHOT_MIN_INTERVAL_HOURS", "24"))
SNAPSHOT_RETENTION_DAYS = int(os.environ.get("SNAPSHOT_RETENTION_DAYS", "400"))
# Raw login records. The rolled-up reach in CredentialAssetLink and the
# forwarded events outlive them, so this is deliberately much shorter.
USAGE_RETENTION_DAYS = int(os.environ.get("USAGE_RETENTION_DAYS", "120"))
EVENT_RETENTION_DAYS = int(os.environ.get("EVENT_RETENTION_DAYS", "730"))

# Downstream forwarding to the enterprise Security Information and Event
# Management platform.
SPLUNK_HEC_URL = os.environ.get("SPLUNK_HEC_URL", "")
SPLUNK_HEC_TOKEN_REFERENCE = os.environ.get("SPLUNK_HEC_TOKEN_REFERENCE", "")
SPLUNK_HEC_INDEX = os.environ.get("SPLUNK_HEC_INDEX", "pam_lifecycle")
SPLUNK_HEC_SOURCETYPE = os.environ.get("SPLUNK_HEC_SOURCETYPE", "pam:lifecycle:json")
SPLUNK_HEC_VERIFY = os.environ.get("PAM_CA_BUNDLE", True)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "format": '{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","message":"%(message)s"}'
        }
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "json"},
    },
    "root": {"handlers": ["console"], "level": os.environ.get("LOG_LEVEL", "INFO")},
    "loggers": {
        "connectors": {"level": "INFO"},
        "collection": {"level": "INFO"},
        "rules": {"level": "INFO"},
    },
}
