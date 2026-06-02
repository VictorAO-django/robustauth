import os

from django.apps import AppConfig


class RobustAuthConfig(AppConfig):
    name = "robustauth"
    verbose_name = "RobustAuth"
    default_auto_field = "django.db.models.BigAutoField"
    path = os.path.dirname(os.path.abspath(__file__))

    def ready(self):
        # Import signal handlers registered by the host application
        # Also connect built-in handlers
        from . import signal_handlers  # noqa: F401