"""
Built-in signal handlers wired up at app startup.
"""
import contextlib

from django.contrib.auth.signals import user_login_failed
from django.core.cache import cache
from django.dispatch import receiver

from . import signals
from .conf import robust_settings


@receiver(user_login_failed)
def track_failed_login(sender, credentials, request, **kwargs):
    if not robust_settings.STORE_FAILED_LOGINS:
        return

    username = credentials.get("username", "")
    ip = _get_ip(request)
    cache_key = f"robustauth:fail:{ip}:{username}"

    count = cache.get(cache_key, 0) + 1
    cache.set(cache_key, count, timeout=robust_settings.FAILED_LOGIN_WINDOW)

    # Try to find the user for audit trail
    from django.contrib.auth import get_user_model

    from .models import LoginHistory

    User = get_user_model()

    user_obj = None
    try:
        # Try to find by username first
        user_obj = User.objects.get(**{User.USERNAME_FIELD: username})
    except (User.DoesNotExist, ValueError):
        # If not found or invalid, try to find by email as fallback
        with contextlib.suppress(User.DoesNotExist, ValueError):
            user_obj = User.objects.get(email=username)

    # Log to DB with user attribution if found
    LoginHistory.objects.create(
        user=user_obj,
        event=LoginHistory.EventType.LOGIN_FAILURE,
        ip_address=ip,
        user_agent=request.META.get("HTTP_USER_AGENT", "") if request else "",
        extra={"username": username, "failure_count": count},
    )

    if count >= robust_settings.FAILED_LOGIN_THRESHOLD:
        signals.brute_force_threshold_hit.send(
            sender=sender,
            username=username,
            ip_address=ip,
            failure_count=count,
        )


def _get_ip(request):
    if request is None:
        return None
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    return xff.split(",")[0].strip() if xff else request.META.get("REMOTE_ADDR")