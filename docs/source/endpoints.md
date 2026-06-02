# API Endpoints

All endpoints are available under wherever you mounted `robustauth.urls`. The examples below assume `path("auth/", include("robustauth.urls"))`.

---

## POST `/auth/login/`

Authenticate with username and password. Returns an access + refresh token pair.

**Authentication required:** No

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
  "access_token": "a3f9c2...",
  "refresh_token": "b7c241...",
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "token_type": "Bearer"
}
```

**Error `400`:**
```json
{
  "non_field_errors": ["Invalid credentials."]
}
```

---

## POST `/auth/token/refresh/`

Exchange a refresh token for a brand new access + refresh token pair. The submitted refresh token is immediately invalidated.

**Authentication required:** No

**Request:**
```json
{
  "refresh_token": "b7c241..."
}
```

**Response `200`:**
```json
{
  "access_token": "d1e4f5...",
  "refresh_token": "f5a8b9...",
  "token_type": "Bearer"
}
```

**Error `400` (expired or invalid):**
```json
{
  "non_field_errors": ["Invalid or expired refresh token."]
}
```

> **Security note:** If a refresh token that has already been used is submitted, RobustAuth detects the reuse, revokes the entire token family, and terminates all sessions for that user. The `token_reuse_detected` signal is fired.

---

## POST `/auth/logout/`

Revoke the current session. The access token and all associated refresh tokens are immediately invalidated.

**Authentication required:** Yes — `Authorization: Bearer <access_token>`

**Response `200`:**
```json
{
  "detail": "Logged out successfully."
}
```

---

## POST `/auth/logout/all/`

Revoke all sessions for the authenticated user. Optionally keep the current session alive.

**Authentication required:** Yes

**Request:**
```json
{
  "keep_current": true
}
```

**Response `200`:**
```json
{
  "detail": "Revoked 3 session(s)."
}
```

---

## GET `/auth/sessions/`

List all active sessions for the authenticated user. The current session is identified with `"is_current": true`.

**Authentication required:** Yes

**Response `200`:**
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "state": "active",
    "ip_address": "41.58.12.34",
    "device_type": "mobile",
    "os_family": "Android",
    "browser_family": "Chrome Mobile",
    "device_name": "Samsung SM-G991",
    "created_at": "2025-06-01T10:23:00Z",
    "last_activity": "2025-06-01T14:05:00Z",
    "is_current": true
  },
  {
    "id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
    "state": "active",
    "ip_address": "41.58.12.34",
    "device_type": "desktop",
    "os_family": "Windows",
    "browser_family": "Firefox",
    "device_name": "Other",
    "created_at": "2025-05-30T08:00:00Z",
    "last_activity": "2025-05-30T09:15:00Z",
    "is_current": false
  }
]
```

---

## DELETE `/auth/sessions/<uuid>/`

Revoke a specific session by its UUID. Users can only revoke their own sessions.

**Authentication required:** Yes

**Response `200`:**
```json
{
  "detail": "Session revoked."
}
```

**Error `404`:**
```json
{
  "detail": "Session not found."
}
```

---

## GET `/auth/history/`

Return the authentication event log for the authenticated user, ordered by most recent first.

**Authentication required:** Yes

**Query params:** `?limit=50` (default: 50)

**Response `200`:**
```json
[
  {
    "id": 5,
    "event": "token_refresh",
    "ip_address": "41.58.12.34",
    "user_agent": "Mozilla/5.0 (Linux; Android 13 ...)",
    "extra": {},
    "timestamp": "2025-06-01T14:05:00Z"
  },
  {
    "id": 4,
    "event": "login_success",
    "ip_address": "41.58.12.34",
    "user_agent": "Mozilla/5.0 (Linux; Android 13 ...)",
    "extra": {},
    "timestamp": "2025-06-01T10:23:00Z"
  },
  {
    "id": 3,
    "event": "login_failure",
    "ip_address": "41.58.12.34",
    "user_agent": "Mozilla/5.0 ...",
    "extra": {"username": "alice", "failure_count": 1},
    "timestamp": "2025-06-01T10:22:00Z"
  }
]
```

**Event types:**

| Event | Description |
|---|---|
| `login_success` | Successful login |
| `login_failure` | Failed login attempt |
| `logout` | Normal logout |
| `token_refresh` | Access token refreshed |
| `token_reuse` | Reuse of an already-used refresh token detected |
| `password_change` | User changed their password |
| `session_revoked` | Session was explicitly revoked |
| `forced_logout` | Session was force-revoked by a policy (e.g. single-session, password change) |