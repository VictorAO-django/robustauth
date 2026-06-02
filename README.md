# RobustAuth

**Modern session-based opaque token authentication for Django REST Framework.**

RobustAuth replaces JWT complexity with secure, database-backed opaque tokens — giving you instant revocation, full session intelligence, and production-grade security controls out of the box.

[![PyPI version](https://badge.fury.io/py/robustauth.svg)](https://pypi.org/project/robustauth/)
[![Django](https://img.shields.io/badge/Django-5.2%20%7C%206.0-green)](https://www.djangoproject.com/)
[![DRF](https://img.shields.io/badge/DRF-3.14%2B-blue)](https://www.django-rest-framework.org/)
[![Docs](https://readthedocs.org/projects/robustauth/badge/?version=latest)](https://robustauth.readthedocs.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Why RobustAuth?

| Feature | DRF TokenAuth | SimpleJWT | **RobustAuth** |
|---|---|---|---|
| Instant token revocation | ✅ | ❌ (wait for expiry) | ✅ |
| Refresh token rotation | ❌ | ✅ | ✅ |
| Reuse detection | ❌ | ❌ | ✅ |
| Multi-device session tracking | ❌ | ❌ | ✅ |
| Single-session enforcement | ❌ | ❌ | ✅ |
| Login / audit history | ❌ | ❌ | ✅ |
| Device & browser detection | ❌ | ❌ | ✅ (optional) |
| Hashed token storage | ❌ | N/A | ✅ |
| Sliding sessions | ❌ | ❌ | ✅ |
| Django admin integration | ✅ | ❌ | ✅ |

---

## Installation

```bash
pip install robustauth

# Optional: device/browser detection
pip install robustauth[device]
```

Add to `INSTALLED_APPS`:

```python
INSTALLED_APPS = [
    ...
    "robustauth",
]
```

Run migrations:

```bash
python manage.py migrate
```

Add URL patterns:

```python
# urls.py
from django.urls import path, include

urlpatterns = [
    path("auth/", include("robustauth.urls")),
    ...
]
```

---

## Quick Start

### 1. Configure (optional — sensible defaults apply)

```python
# settings.py
ROBUST_AUTH = {
    "ACCESS_TOKEN_TTL": 900,          # 15 min
    "REFRESH_TOKEN_TTL": 604800,      # 7 days
    "SESSION_POLICY": "single",       # one device at a time
    "ROTATE_REFRESH_TOKENS": True,
    "REVOKE_ON_PASSWORD_CHANGE": True,
    "TRACK_IPS": True,
    "TRACK_USER_AGENTS": True,
    "MAX_SESSIONS": 3,                # used when SESSION_POLICY = "max_count"
}
```

### 2. Set authentication on your views

```python
# settings.py
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "robustauth.authentication.RobustTokenAuthentication",
    ],
}
```

Or per-view:

```python
from robustauth.authentication import RobustTokenAuthentication

class MyView(APIView):
    authentication_classes = [RobustTokenAuthentication]
    permission_classes = [IsAuthenticated]
```

---

## API Endpoints

All endpoints are prefixed with wherever you mounted `robustauth.urls`.

### `POST /auth/login/`

Authenticate a user and receive token pair.

**Request:**
```json
{
  "username": "alice",
  "password": "secret"
}
```

**Response `200`:**
```json
{
  "access_token": "a3f9...",
  "refresh_token": "b7c2...",
  "session_id": "550e8400-e29b-...",
  "token_type": "Bearer"
}
```

---

### `POST /auth/token/refresh/`

Exchange a refresh token for a new token pair. The old refresh token is invalidated.

**Request:**
```json
{ "refresh_token": "b7c2..." }
```

**Response `200`:**
```json
{
  "access_token": "d1e4...",
  "refresh_token": "f5a8...",
  "token_type": "Bearer"
}
```

---

### `POST /auth/logout/`

Revoke the current session. Requires `Authorization: Bearer <access_token>`.

**Response `200`:**
```json
{ "detail": "Logged out successfully." }
```

---

### `POST /auth/logout/all/`

Revoke all sessions (optionally keep the current one alive).

**Request:**
```json
{ "keep_current": true }
```

---

### `GET /auth/sessions/`

List all active sessions for the authenticated user.

**Response:**
```json
[
  {
    "id": "550e8400-...",
    "state": "active",
    "ip_address": "41.58.12.34",
    "device_type": "mobile",
    "os_family": "Android",
    "browser_family": "Chrome Mobile",
    "device_name": "Samsung SM-G991",
    "created_at": "2024-01-15T10:23:00Z",
    "last_activity": "2024-01-15T14:05:00Z",
    "is_current": true
  }
]
```

---

### `DELETE /auth/sessions/<uuid>/`

Revoke a specific session by ID.

---

### `GET /auth/history/`

Return the authentication event log for the authenticated user.

**Query params:** `?limit=50`

**Response:**
```json
[
  {
    "id": 1,
    "event": "login_success",
    "ip_address": "41.58.12.34",
    "user_agent": "Mozilla/5.0 ...",
    "extra": {},
    "timestamp": "2024-01-15T10:23:00Z"
  },
  ...
]
```

---

## Session Policies

Control concurrent login behaviour via `SESSION_POLICY`:

| Value | Behaviour |
|---|---|
| `"multi"` | Unlimited concurrent sessions (default) |
| `"single"` | Only one active session per user — new login revokes all others |
| `"max_count"` | At most `MAX_SESSIONS` active sessions; oldest revoked when limit hit |

```python
ROBUST_AUTH = {
    "SESSION_POLICY": "max_count",
    "MAX_SESSIONS": 3,
    "REVOKE_OLDEST_ON_LIMIT": True,   # False → raise error instead
}
```

---

## Signals

Hook into authentication events in your own apps:

```python
from robustauth import signals
from django.dispatch import receiver

@receiver(signals.token_reuse_detected)
def alert_security(sender, user, session, ip_address, **kwargs):
    # Send email, create alert, block IP, etc.
    SecurityAlert.objects.create(user=user, ip=ip_address)

@receiver(signals.brute_force_threshold_hit)
def handle_brute_force(sender, username, ip_address, failure_count, **kwargs):
    BlockedIP.objects.get_or_create(ip=ip_address)

@receiver(signals.user_logged_in)
def on_login(sender, user, session, **kwargs):
    send_new_login_email(user, session)

@receiver(signals.session_limit_reached)
def on_limit(sender, user, active_sessions, **kwargs):
    notify_user(user, "You've reached the maximum number of active sessions.")
```

Available signals:

| Signal | kwargs |
|---|---|
| `user_logged_in` | `user`, `session` |
| `user_logged_out` | `user`, `session` |
| `token_reuse_detected` | `user`, `session`, `ip_address` |
| `session_limit_reached` | `user`, `active_sessions` |
| `brute_force_threshold_hit` | `username`, `ip_address`, `failure_count` |

---

## Password Change Integration

Automatically revoke all other sessions on password change:

```python
from robustauth.session_manager import SessionManager

def change_password_view(request):
    # ... your password change logic ...
    user.set_password(new_password)
    user.save()

    # Revoke all sessions except the current one
    current_session = request.auth.session  # if using RobustTokenAuthentication
    SessionManager.on_password_change(user, current_session=current_session)
```

---

## Middleware (optional)

Attach `request.robust_session` to all requests:

```python
MIDDLEWARE = [
    ...
    "robustauth.middleware.RobustAuthMiddleware",
]
```

Then in any view:

```python
def my_view(request):
    session = request.robust_session  # Session object or None
```

---

## Cleanup

Remove expired tokens and prune history. Add to your cron or Celery beat:

```bash
python manage.py robustauth_cleanup

# Preview without deleting
python manage.py robustauth_cleanup --dry-run
```

Example Celery beat config:

```python
CELERY_BEAT_SCHEDULE = {
    "robustauth-cleanup": {
        "task": "your_app.tasks.robustauth_cleanup",
        "schedule": crontab(hour=3, minute=0),  # daily at 3am
    }
}
```

---

## Configuration Reference

| Setting | Default | Description |
|---|---|---|
| `ACCESS_TOKEN_TTL` | `900` | Access token lifetime in seconds |
| `REFRESH_TOKEN_TTL` | `604800` | Refresh token lifetime in seconds |
| `SESSION_POLICY` | `"multi"` | `"single"` / `"multi"` / `"max_count"` |
| `MAX_SESSIONS` | `5` | Max concurrent sessions (`max_count` policy) |
| `REVOKE_OLDEST_ON_LIMIT` | `True` | Auto-revoke oldest when limit hit |
| `ROTATE_REFRESH_TOKENS` | `True` | Issue new refresh token on each use |
| `REFRESH_TOKEN_REUSE_DETECTION` | `True` | Revoke family + all sessions on reuse |
| `REVOKE_ON_PASSWORD_CHANGE` | `True` | Revoke all sessions on password change |
| `HASH_TOKENS` | `True` | Store `sha256(token)` instead of plaintext |
| `TOKEN_BYTES` | `32` | Random bytes for token generation |
| `TRACK_IPS` | `True` | Store client IP on sessions |
| `TRACK_USER_AGENTS` | `True` | Store User-Agent header |
| `TRACK_DEVICE_INFO` | `True` | Parse OS/browser from UA (`ua-parser` required) |
| `STORE_LOGIN_HISTORY` | `True` | Log successful logins |
| `STORE_LOGOUT_HISTORY` | `True` | Log logouts |
| `STORE_FAILED_LOGINS` | `True` | Log failed login attempts |
| `MAX_HISTORY_ENTRIES` | `100` | Max history rows kept per user |
| `FAILED_LOGIN_THRESHOLD` | `5` | Failures before `brute_force_threshold_hit` fires |
| `FAILED_LOGIN_WINDOW` | `300` | Window in seconds for counting failures |
| `SLIDING_SESSION` | `False` | Reset access token expiry on activity |
| `SLIDING_SESSION_TTL` | `1800` | Inactivity timeout for sliding sessions |

---

## Running Tests

```bash
pip install -e ".[dev]"
pytest
```

---

## Changelog

### 0.1.0
- Initial release
- Opaque token authentication with hashed storage
- Access + refresh token pair with rotation
- Refresh token reuse detection with family revocation
- Session policies: single / multi / max_count
- Device and browser fingerprinting
- Login / logout / failed login history
- Brute-force threshold signal
- Sliding sessions
- Password change revocation
- Django admin integration
- `robustauth_cleanup` management command

---

## License

MIT — see [LICENSE](LICENSE).