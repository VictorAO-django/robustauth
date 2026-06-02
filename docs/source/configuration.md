# Configuration

All RobustAuth settings live under a single `ROBUST_AUTH` dict in your Django `settings.py`. Every setting has a sensible default — you only need to override what you want to change.

```python
ROBUST_AUTH = {
    # your overrides here
}
```

---

## Token Lifetimes

| Setting | Default | Description |
|---|---|---|
| `ACCESS_TOKEN_TTL` | `900` | Access token lifetime in seconds (15 min) |
| `REFRESH_TOKEN_TTL` | `604800` | Refresh token lifetime in seconds (7 days) |
| `TOKEN_BYTES` | `32` | Random bytes used to generate each token |

---

## Session Policy

| Setting | Default | Description |
|---|---|---|
| `SESSION_POLICY` | `"multi"` | `"single"` / `"multi"` / `"max_count"` — see [Session Policies](session_policies.md) |
| `MAX_SESSIONS` | `5` | Maximum concurrent sessions (used when `SESSION_POLICY = "max_count"`) |
| `REVOKE_OLDEST_ON_LIMIT` | `True` | When `True`, oldest session is auto-revoked when limit is hit. When `False`, raises an error instead |

---

## Token Security

| Setting | Default | Description |
|---|---|---|
| `HASH_TOKENS` | `True` | Store `sha256(token)` in the database instead of the raw token |
| `ROTATE_REFRESH_TOKENS` | `True` | Issue a new refresh token on every use; old token is immediately invalidated |
| `REFRESH_TOKEN_REUSE_DETECTION` | `True` | If an already-used refresh token is presented again, revoke the entire token family and all sessions |

---

## Password Change & Reset

| Setting | Default | Description |
|---|---|---|
| `REVOKE_ON_PASSWORD_CHANGE` | `True` | Revoke all **other** sessions when a user changes their password. Current session is kept alive |
| `REFRESH_TOKEN_ON_PASSWORD_CHANGE` | `True` | Issue a fresh token pair to the current session after a password change, so the client stays logged in without interruption |
| `REVOKE_ON_PASSWORD_RESET` | `True` | Revoke **all** sessions including current on password reset. Reset is a stronger security event — forces re-login everywhere |
| `REFRESH_TOKEN_ON_PASSWORD_RESET` | `False` | Issue a new token pair immediately after reset so the user lands logged in. `False` by default — forces re-login instead |

### Behaviour matrix

| Event | `REVOKE_*` | `REFRESH_TOKEN_*` | Result |
|---|---|---|---|
| Password **change** | `True` | `True` (default) | Other sessions killed, current session gets new tokens — user stays logged in |
| Password **change** | `True` | `False` | Other sessions killed, current session token unchanged |
| Password **change** | `False` | `True` | No revocation, current session gets new tokens |
| Password **reset** | `True` (default) | `False` (default) | All sessions killed — user must log in again |
| Password **reset** | `True` | `True` | All sessions killed, then new session + tokens issued — user lands logged in |
| Password **reset** | `False` | `False` | No sessions touched, no new tokens |

### How to call from your views

```python
from robustauth.session_manager import SessionManager

# After password change — pass current session to keep it alive
def change_password(request):
    user.set_password(new_password)
    user.save()
    new_pair = SessionManager.on_password_change(
        user,
        current_session=request.auth.session,
    )
    if new_pair:
        # Send new tokens back to the client
        return Response({
            "access_token":  new_pair.access_token,
            "refresh_token": new_pair.refresh_token,
        })
    return Response({"detail": "Password changed."})


# After password reset — no current session (user came via email link)
def reset_password(request):
    user.set_password(new_password)
    user.save()
    new_pair = SessionManager.on_password_reset(user)
    if new_pair:
        # Log user in immediately after reset
        return Response({
            "access_token":  new_pair.access_token,
            "refresh_token": new_pair.refresh_token,
        })
    return Response({"detail": "Password reset. Please log in."})
```

---

## Tracking

| Setting | Default | Description |
|---|---|---|
| `TRACK_IPS` | `True` | Store the client IP address on each session |
| `TRACK_USER_AGENTS` | `True` | Store the raw `User-Agent` header on each session |
| `TRACK_DEVICE_INFO` | `True` | Parse OS, browser, and device type from the User-Agent (requires `pip install robustauth[device]`) |

---

## Audit History

| Setting | Default | Description |
|---|---|---|
| `STORE_LOGIN_HISTORY` | `True` | Log successful logins to `LoginHistory` |
| `STORE_LOGOUT_HISTORY` | `True` | Log logout events to `LoginHistory` |
| `STORE_FAILED_LOGINS` | `True` | Log failed login attempts to `LoginHistory` |
| `MAX_HISTORY_ENTRIES` | `100` | Maximum `LoginHistory` rows kept per user; older rows pruned by `robustauth_cleanup` |

---

## Brute-Force Protection

| Setting | Default | Description |
|---|---|---|
| `FAILED_LOGIN_THRESHOLD` | `5` | Number of failed logins within `FAILED_LOGIN_WINDOW` before `brute_force_threshold_hit` signal fires |
| `FAILED_LOGIN_WINDOW` | `300` | Time window in seconds for counting failed logins |

---

## Sliding Sessions

| Setting | Default | Description |
|---|---|---|
| `SLIDING_SESSION` | `False` | When `True`, both access and refresh token expiry are reset on every authenticated request |
| `SLIDING_SESSION_TTL` | `1800` | Token extension in seconds when sliding sessions are enabled. With inactivity > 30 min, tokens expire (30 min) |

---

## Full Example

```python
ROBUST_AUTH = {
    # Tokens
    "ACCESS_TOKEN_TTL": 900,
    "REFRESH_TOKEN_TTL": 604800,
    "TOKEN_BYTES": 32,

    # Session policy
    "SESSION_POLICY": "max_count",
    "MAX_SESSIONS": 3,
    "REVOKE_OLDEST_ON_LIMIT": True,

    # Security
    "HASH_TOKENS": True,
    "ROTATE_REFRESH_TOKENS": True,
    "REFRESH_TOKEN_REUSE_DETECTION": True,
    "REVOKE_ON_PASSWORD_CHANGE": True,

    # Tracking
    "TRACK_IPS": True,
    "TRACK_USER_AGENTS": True,
    "TRACK_DEVICE_INFO": True,

    # History
    "STORE_LOGIN_HISTORY": True,
    "STORE_LOGOUT_HISTORY": True,
    "STORE_FAILED_LOGINS": True,
    "MAX_HISTORY_ENTRIES": 100,

    # Brute-force
    "FAILED_LOGIN_THRESHOLD": 5,
    "FAILED_LOGIN_WINDOW": 300,

    # Sliding sessions
    "SLIDING_SESSION": False,
    "SLIDING_SESSION_TTL": 1800,
}
```