"""
Management command: robustauth_cleanup

Removes expired AccessTokens, used/revoked RefreshTokens,
expired Sessions, and LoginHistory entries beyond MAX_HISTORY_ENTRIES.

Run periodically via cron / Celery beat::

    python manage.py robustauth_cleanup
    python manage.py robustauth_cleanup --dry-run
"""
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from robustauth.conf import robust_settings
from robustauth.models import AccessToken, LoginHistory, RefreshToken, Session

User = get_user_model()


class Command(BaseCommand):
    help = "Remove expired RobustAuth tokens, sessions, and excess history."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report what would be deleted without deleting anything.",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        now = timezone.now()

        if dry_run:
            self.stdout.write(self.style.WARNING("DRY RUN — nothing will be deleted.\n"))

        with transaction.atomic():
            # 1. Expired AccessTokens
            expired_at = AccessToken.objects.filter(expires_at__lte=now)
            count_at = expired_at.count()
            if not dry_run:
                expired_at.delete()
            self._report("Expired AccessTokens", count_at, dry_run)

            # 2. Used / revoked RefreshTokens older than REFRESH_TOKEN_TTL
            stale_rt = RefreshToken.objects.filter(
                expires_at__lte=now
            ) | RefreshToken.objects.filter(is_revoked=True)
            # Deduplicate (union query)
            stale_rt = RefreshToken.objects.filter(
                id__in=stale_rt.values("id")
            )
            count_rt = stale_rt.count()
            if not dry_run:
                stale_rt.delete()
            self._report("Stale RefreshTokens", count_rt, dry_run)

            # 3. Revoked / expired Sessions with no remaining tokens
            dead_sessions = Session.objects.filter(
                state__in=[Session.State.REVOKED, Session.State.EXPIRED]
            )
            count_ss = dead_sessions.count()
            if not dry_run:
                dead_sessions.delete()
            self._report("Dead Sessions", count_ss, dry_run)

            # 4. Prune LoginHistory beyond MAX_HISTORY_ENTRIES per user
            max_entries = robust_settings.MAX_HISTORY_ENTRIES
            pruned_history = 0
            for user in User.objects.iterator():
                entries = list(
                    LoginHistory.objects.filter(user=user)
                    .order_by("-timestamp")
                    .values_list("id", flat=True)
                )
                if len(entries) > max_entries:
                    to_delete = entries[max_entries:]
                    pruned_history += len(to_delete)
                    if not dry_run:
                        LoginHistory.objects.filter(id__in=to_delete).delete()
            self._report("Pruned LoginHistory rows", pruned_history, dry_run)

        self.stdout.write(self.style.SUCCESS("\nCleanup complete."))

    def _report(self, label: str, count: int, dry_run: bool):
        verb = "Would delete" if dry_run else "Deleted"
        colour = self.style.WARNING if dry_run else self.style.SUCCESS
        self.stdout.write(colour(f"  {verb} {count:,} {label}"))