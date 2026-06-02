# Session Policies

RobustAuth gives you full control over how many concurrent sessions a user is allowed to have. Configure via the `SESSION_POLICY` setting.

---

## `"multi"` (default)

No restrictions. A user can have unlimited active sessions simultaneously — one per device, browser, or app install.

```python
ROBUST_AUTH = {
    "SESSION_POLICY": "multi",
}
```

**Use case:** Most APIs, mobile apps, SaaS platforms where users legitimately log in from many devices.

---

## `"single"`

Only one active session is allowed per user at any time. When a new login occurs, **all existing sessions are immediately revoked** before the new one is created.

```python
ROBUST_AUTH = {
    "SESSION_POLICY": "single",
}
```

**Use case:** Banking-style applications, high-security dashboards, or apps where you want to prevent shared account access.

> The `forced_logout` event is recorded in `LoginHistory` for every session revoked this way.

---

## `"max_count"`

At most `MAX_SESSIONS` active sessions are allowed per user. When a new login would exceed this limit, behaviour depends on `REVOKE_OLDEST_ON_LIMIT`:

### With `REVOKE_OLDEST_ON_LIMIT = True` (default)

The oldest session is automatically revoked to make room for the new one.

```python
ROBUST_AUTH = {
    "SESSION_POLICY": "max_count",
    "MAX_SESSIONS": 3,
    "REVOKE_OLDEST_ON_LIMIT": True,
}
```

### With `REVOKE_OLDEST_ON_LIMIT = False`

The login is rejected with a `ValueError` and the `session_limit_reached` signal fires. You handle it — for example, by returning a `403` with a message asking the user to log out from another device.

```python
ROBUST_AUTH = {
    "SESSION_POLICY": "max_count",
    "MAX_SESSIONS": 5,
    "REVOKE_OLDEST_ON_LIMIT": False,
}
```

```python
# Handle in your login view or via signal
from robustauth import signals
from django.dispatch import receiver

@receiver(signals.session_limit_reached)
def handle_limit(sender, user, active_sessions, **kwargs):
    # notify user, return custom error, etc.
    pass
```

**Use case:** Streaming services, team tools, or apps that want to limit device count without being as strict as `"single"`.

---

## Comparison

| Policy | New login behaviour | Existing sessions |
|---|---|---|
| `multi` | Always allowed | Untouched |
| `single` | Always allowed | All revoked |
| `max_count` + revoke oldest | Always allowed | Oldest revoked if over limit |
| `max_count` + no auto-revoke | Rejected if over limit | Untouched |

---

## Password Change Behaviour

Regardless of session policy, when `REVOKE_ON_PASSWORD_CHANGE = True` (default), all sessions **except the current one** are revoked when a user changes their password. Call `SessionManager.on_password_change()` from your password change view:

```python
from robustauth.session_manager import SessionManager

def change_password(request):
    user.set_password(new_password)
    user.save()
    SessionManager.on_password_change(user, current_session=request.auth.session)
```