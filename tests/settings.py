"""
Minimal Django settings for running the RobustAuth test suite.

pytest --ds=tests.settings -v
"""
SECRET_KEY = "test-secret-key-not-for-production"
DEBUG = True

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "rest_framework",
    "robustauth",
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}

ROBUST_AUTH = {
    "ACCESS_TOKEN_TTL": 900,
    "REFRESH_TOKEN_TTL": 604800,
    "SESSION_POLICY": "multi",
    "ROTATE_REFRESH_TOKENS": True,
    "REVOKE_ON_PASSWORD_CHANGE": True,
    "TRACK_IPS": True,
    "TRACK_USER_AGENTS": True,
    "HASH_TOKENS": True,
    "STORE_LOGIN_HISTORY": True,
    "STORE_LOGOUT_HISTORY": True,
    "STORE_FAILED_LOGINS": True,
    "MAX_SESSIONS": 5,
    "REVOKE_OLDEST_ON_LIMIT": True,
    "REFRESH_TOKEN_REUSE_DETECTION": True,
}