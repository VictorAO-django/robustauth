# Installation

## 1. Install the package

```bash
pip install robustauth
```

For device and browser detection (OS, browser family, device type):

```bash
pip install robustauth[device]
```

---

## 2. Add to INSTALLED_APPS

```python
# settings.py
INSTALLED_APPS = [
    ...
    "rest_framework",
    "robustauth",
]
```

---

## 3. Configure DRF authentication

```python
# settings.py
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "robustauth.authentication.RobustTokenAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
}
```

---

## 4. Add middleware (optional but recommended)

Attaches `request.robust_session` to every authenticated request:

```python
MIDDLEWARE = [
    ...
    "robustauth.middleware.RobustAuthMiddleware",
]
```

---

## 5. Mount URL patterns

```python
# urls.py
from django.urls import path, include

urlpatterns = [
    path("auth/", include("robustauth.urls")),
    ...
]
```

---

## 6. Run migrations

```bash
python manage.py migrate
```

---

## 7. Add your configuration (optional)

See [Configuration](configuration.md) for all available settings. A minimal secure setup:

```python
ROBUST_AUTH = {
    "SESSION_POLICY": "multi",
    "ROTATE_REFRESH_TOKENS": True,
    "REVOKE_ON_PASSWORD_CHANGE": True,
    "TRACK_IPS": True,
}
```

---

## Verifying installation

Start your server and hit the login endpoint:

```bash
python manage.py runserver

curl -X POST http://localhost:8000/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "yourpassword"}'
```

You should receive an `access_token`, `refresh_token`, and `session_id`.

---

## Periodic cleanup

Add the cleanup command to your cron or Celery beat to remove expired tokens and prune old history:

```bash
# Run daily
python manage.py robustauth_cleanup
```