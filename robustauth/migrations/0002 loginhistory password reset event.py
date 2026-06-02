"""
Add PASSWORD_RESET to LoginHistory.EventType choices.
This is a data migration only — no schema change needed since
event is a CharField with no DB-level constraint on choices.
"""
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("robustauth", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="loginhistory",
            name="event",
            field=models.CharField(
                choices=[
                    ("login_success",   "Login Success"),
                    ("login_failure",   "Login Failure"),
                    ("logout",          "Logout"),
                    ("token_refresh",   "Token Refresh"),
                    ("token_reuse",     "Token Reuse Detected"),
                    ("password_change", "Password Changed"),
                    ("password_reset",  "Password Reset"),
                    ("session_revoked", "Session Revoked"),
                    ("forced_logout",   "Forced Logout"),
                ],
                db_index=True,
                max_length=32,
            ),
        ),
    ]