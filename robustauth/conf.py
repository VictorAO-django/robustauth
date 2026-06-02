"""
RobustAuth configuration with sensible defaults.
All settings are read from Django settings.ROBUST_AUTH dict.
"""
from django.conf import settings

DEFAULTS = {
    # Token lifetimes (seconds)
    "ACCESS_TOKEN_TTL": 900,           # 15 minutes
    "REFRESH_TOKEN_TTL": 604800,       # 7 days

    # Session policy: "single" | "multi" | "max_count"
    "SESSION_POLICY": "multi",
    "MAX_SESSIONS": 5,                 # used when SESSION_POLICY = "max_count"
    "REVOKE_OLDEST_ON_LIMIT": True,    # auto-revoke oldest when limit hit

    # Token security
    "ROTATE_REFRESH_TOKENS": True,
    "REFRESH_TOKEN_REUSE_DETECTION": True,   # flag & revoke family on reuse
    "HASH_TOKENS": True,               # store sha256(token) in DB

    # Password change behaviour
    "REVOKE_ON_PASSWORD_CHANGE": True,  # revoke other sessions on password change
    "REFRESH_TOKEN_ON_PASSWORD_CHANGE": True,  # issue fresh token pair after change
    "REVOKE_ON_PASSWORD_RESET": True,  # revoke ALL sessions (including current)
    "REFRESH_TOKEN_ON_PASSWORD_RESET": False,  # issue fresh token pair after reset

    # Tracking
    "TRACK_IPS": True,
    "TRACK_USER_AGENTS": True,
    "TRACK_DEVICE_INFO": True,         # parsed OS/browser from UA string

    # Login/audit history
    "STORE_LOGIN_HISTORY": True,
    "STORE_LOGOUT_HISTORY": True,
    "STORE_FAILED_LOGINS": True,
    "MAX_HISTORY_ENTRIES": 100,        # per user, older entries pruned

    # Brute-force
    "FAILED_LOGIN_THRESHOLD": 5,       # failures before lockout signal fires
    "FAILED_LOGIN_WINDOW": 300,        # seconds

    # Sliding session: reset expiry on activity
    "SLIDING_SESSION": False,
    "SLIDING_SESSION_TTL": 1800,       # 30 min inactivity = expired

    # Token byte length (before hex encoding)
    "TOKEN_BYTES": 32,

    # Login serializer — swap to change credential fields (username/email/phone/custom)
    # Must be a dotted Python path to a subclass of BaseLoginSerializer
    "LOGIN_SERIALIZER": "robust_auth.serializers.UsernameLoginSerializer",
}


class RobustAuthSettings:
    def __init__(self):
        self._user = getattr(settings, "ROBUST_AUTH", {})

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        if name not in DEFAULTS:
            raise AttributeError(f"RobustAuth has no setting '{name}'")
        return self._user.get(name, DEFAULTS[name])


robust_settings = RobustAuthSettings()