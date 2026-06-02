"""
Initial migration for RobustAuth.
"""
import uuid
import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Session",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("state", models.CharField(choices=[("active", "Active"), ("revoked", "Revoked"), ("expired", "Expired")], db_index=True, default="active", max_length=10)),
                ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
                ("user_agent", models.TextField(blank=True, default="")),
                ("device_type", models.CharField(blank=True, default="", max_length=64)),
                ("os_family", models.CharField(blank=True, default="", max_length=64)),
                ("browser_family", models.CharField(blank=True, default="", max_length=64)),
                ("device_name", models.CharField(blank=True, default="", max_length=128)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("last_activity", models.DateTimeField(auto_now_add=True)),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="robust_sessions", to=settings.AUTH_USER_MODEL)),
            ],
            options={"ordering": ["-created_at"]},
        ),
        migrations.AddIndex(
            model_name="session",
            index=models.Index(fields=["user", "state"], name="robustauth_session_user_state_idx"),
        ),
        migrations.CreateModel(
            name="AccessToken",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("token_hash", models.CharField(db_index=True, max_length=64, unique=True)),
                ("expires_at", models.DateTimeField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("session", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="access_token", to="robustauth.session")),
            ],
            options={"ordering": ["-created_at"]},
        ),
        migrations.CreateModel(
            name="RefreshToken",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("token_hash", models.CharField(db_index=True, max_length=64, unique=True)),
                ("family_id", models.UUIDField(db_index=True, default=uuid.uuid4)),
                ("is_used", models.BooleanField(db_index=True, default=False)),
                ("is_revoked", models.BooleanField(db_index=True, default=False)),
                ("expires_at", models.DateTimeField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("session", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="refresh_tokens", to="robustauth.session")),
                ("parent", models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="child", to="robustauth.refreshtoken")),
            ],
            options={"ordering": ["-created_at"]},
        ),
        migrations.CreateModel(
            name="LoginHistory",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("event", models.CharField(choices=[
                    ("login_success", "Login Success"),
                    ("login_failure", "Login Failure"),
                    ("logout", "Logout"),
                    ("token_refresh", "Token Refresh"),
                    ("token_reuse", "Token Reuse Detected"),
                    ("password_change", "Password Changed"),
                    ("session_revoked", "Session Revoked"),
                    ("forced_logout", "Forced Logout"),
                ], db_index=True, max_length=32)),
                ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
                ("user_agent", models.TextField(blank=True, default="")),
                ("extra", models.JSONField(blank=True, default=dict)),
                ("timestamp", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("session", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="history", to="robustauth.session")),
                ("user", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name="robustauth_history", to=settings.AUTH_USER_MODEL)),
            ],
            options={"ordering": ["-timestamp"]},
        ),
        migrations.AddIndex(
            model_name="loginhistory",
            index=models.Index(fields=["user", "event"], name="robustauth_history_user_event_idx"),
        ),
        migrations.AddIndex(
            model_name="loginhistory",
            index=models.Index(fields=["user", "timestamp"], name="robustauth_history_user_ts_idx"),
        ),
    ]