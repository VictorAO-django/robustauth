# RobustAuth Documentation

**Modern session-based opaque token authentication for Django REST Framework.**

RobustAuth replaces JWT complexity with secure, database-backed opaque tokens — giving you instant revocation, full session intelligence, and production-grade security controls out of the box.

---

## Why RobustAuth?

Most Django auth packages make you choose between simplicity and power. DRF's built-in `TokenAuthentication` is simple but has no revocation, no sessions, no history. SimpleJWT adds refresh tokens but locks you into JWT — which can't be instantly revoked.

RobustAuth gives you the best of both worlds: the simplicity of opaque tokens with the full session intelligence of a modern auth system.

---

## Documentation

- [Installation](installation.md) — get up and running in minutes
- [Configuration](configuration.md) — all available settings with defaults
- [API Endpoints](endpoints.md) — full REST API reference
- [Session Policies](session_policies.md) — controlling concurrent logins
- [Signals](signals.md) — hooking into authentication events
- [Changelog](changelog.md) — version history

---

## Quick Example

```python
# settings.py
INSTALLED_APPS = [
    ...
    "rest_framework",
    "robustauth",
]

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "robustauth.authentication.RobustTokenAuthentication",
    ],
}

ROBUST_AUTH = {
    "SESSION_POLICY": "single",   # one active session per user
    "ROTATE_REFRESH_TOKENS": True,
    "TRACK_IPS": True,
}
```

```bash
# Login
curl -X POST http://localhost:8000/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "secret"}'

# Response
{
  "access_token": "a3f9...",
  "refresh_token": "b7c2...",
  "session_id": "550e8400-...",
  "token_type": "Bearer"
}
```

---

## Requirements

- Python 3.10+
- Django 4.2+
- Django REST Framework 3.14+
- `user-agents` (optional, for device/browser detection)

```{toctree}
:maxdepth: 2
:caption: Contents:

installation
configuration
endpoints
session_policies
signals
changelog
```