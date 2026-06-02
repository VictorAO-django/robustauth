# Signals

RobustAuth fires Django signals at key authentication events. Connect to them in your own apps to add custom logic — alerting, rate limiting, analytics, notifications, and more — without touching RobustAuth's internals.

---

## Importing signals

```python
from robustauth import signals
from django.dispatch import receiver
```

---

## `user_logged_in`

Fired after a new session is created (successful login).

**kwargs:** `user`, `session`

```python
@receiver(signals.user_logged_in)
def on_login(sender, user, session, **kwargs):
    send_new_login_notification(
        user=user,
        ip=session.ip_address,
        device=session.device_name,
        os=session.os_family,
    )
```

---

## `user_logged_out`

Fired when any session is revoked — normal logout, forced logout, or password change revocation.

**kwargs:** `user`, `session`

```python
@receiver(signals.user_logged_out)
def on_logout(sender, user, session, **kwargs):
    analytics.track(user.id, "session_ended", {
        "session_id": str(session.id),
        "duration": (timezone.now() - session.created_at).seconds,
    })
```

---

## `token_reuse_detected`

Fired when a refresh token that has already been used is presented again. This is a strong signal of token theft. When this fires, RobustAuth has already revoked the entire token family and all sessions for the user.

**kwargs:** `user`, `session`, `ip_address`

```python
@receiver(signals.token_reuse_detected)
def on_token_reuse(sender, user, session, ip_address, **kwargs):
    SecurityAlert.objects.create(
        user=user,
        kind="token_reuse",
        ip_address=ip_address,
    )
    send_security_email(user, "Someone may have stolen your session token.")
```

---

## `session_limit_reached`

Fired when a user hits `MAX_SESSIONS` and `REVOKE_OLDEST_ON_LIMIT = False`. The new login has been blocked at this point. Use this signal to return a custom error or notify the user.

**kwargs:** `user`, `active_sessions`

```python
@receiver(signals.session_limit_reached)
def on_limit_reached(sender, user, active_sessions, **kwargs):
    # active_sessions is a list of Session objects
    send_push_notification(
        user,
        f"Login blocked — you already have {len(active_sessions)} active sessions. "
        "Please log out from another device."
    )
```

---

## `brute_force_threshold_hit`

Fired when the number of failed login attempts for a given username + IP combination exceeds `FAILED_LOGIN_THRESHOLD` within `FAILED_LOGIN_WINDOW` seconds.

**kwargs:** `username`, `ip_address`, `failure_count`

```python
@receiver(signals.brute_force_threshold_hit)
def on_brute_force(sender, username, ip_address, failure_count, **kwargs):
    BlockedIP.objects.get_or_create(ip=ip_address)
    notify_security_team(
        f"{failure_count} failed logins for '{username}' from {ip_address}"
    )
```

---

## `password_changed`

Fired after `SessionManager.on_password_change()` completes. Other sessions have already been revoked at this point. Use this to notify the user.

**kwargs:** `user`, `current_session`, `new_pair`

```python
@receiver(signals.password_changed)
def on_password_changed(sender, user, current_session, new_pair, **kwargs):
    send_email(user, "Your password was changed.")
    # new_pair is an AuthTokenPair if REFRESH_TOKEN_ON_PASSWORD_CHANGE=True, else None
```

---

## `password_reset`

Fired after `SessionManager.on_password_reset()` completes. All sessions have already been revoked at this point.

**kwargs:** `user`, `new_pair`

```python
@receiver(signals.password_reset)
def on_password_reset(sender, user, new_pair, **kwargs):
    send_email(user, "Your password was reset.")
    # new_pair is an AuthTokenPair if REFRESH_TOKEN_ON_PASSWORD_RESET=True, else None
```

---

## Summary

| Signal | When it fires | Key kwargs |
|---|---|---|
| `user_logged_in` | Successful login | `user`, `session` |
| `user_logged_out` | Any session revocation | `user`, `session` |
| `token_reuse_detected` | Reused refresh token detected | `user`, `session`, `ip_address` |
| `session_limit_reached` | Max sessions hit (no auto-revoke) | `user`, `active_sessions` |
| `brute_force_threshold_hit` | Too many failed logins | `username`, `ip_address`, `failure_count` |
| `password_changed` | Password change completed | `user`, `current_session`, `new_pair` |
| `password_reset` | Password reset completed | `user`, `new_pair` |

---

## Registering signal handlers

The recommended place for your signal handlers is in a `signals.py` file inside your app, connected in `AppConfig.ready()`:

```python
# yourapp/apps.py
from django.apps import AppConfig

class YourAppConfig(AppConfig):
    name = "yourapp"

    def ready(self):
        import yourapp.signal_handlers  # noqa: F401
```