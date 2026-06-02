"""
RobustAuth models.

AccessToken  – short-lived opaque token attached to a Session
RefreshToken – long-lived token used to issue new AccessTokens; rotated on use
Session      – logical authentication session (one per device/login)
LoginHistory – immutable audit record for every login / logout / failure
"""
import hashlib
import secrets
import uuid
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db import models, transaction
from django.utils import timezone

from .conf import robust_settings

User = get_user_model()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _generate_token() -> str:
    """Return a URL-safe random hex token."""
    return secrets.token_hex(robust_settings.TOKEN_BYTES)


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _access_expiry():
    return timezone.now() + timedelta(seconds=robust_settings.ACCESS_TOKEN_TTL)


def _refresh_expiry():
    return timezone.now() + timedelta(seconds=robust_settings.REFRESH_TOKEN_TTL)


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

class Session(models.Model):
    """
    Represents one authenticated session (one device / browser / app install).
    """

    class State(models.TextChoices):
        ACTIVE = "active", "Active"
        REVOKED = "revoked", "Revoked"
        EXPIRED = "expired", "Expired"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="robust_sessions"
    )
    state = models.CharField(
        max_length=10, choices=State.choices, default=State.ACTIVE, db_index=True
    )

    # Device / network fingerprint
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, default="")
    device_type = models.CharField(max_length=64, blank=True, default="")   # mobile/desktop/tablet
    os_family = models.CharField(max_length=64, blank=True, default="")
    browser_family = models.CharField(max_length=64, blank=True, default="")
    device_name = models.CharField(max_length=128, blank=True, default="")

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "state"]),
        ]

    def __str__(self):
        return f"Session({self.user_id}, {self.state}, {self.ip_address})"

    # ------------------------------------------------------------------
    def is_active(self) -> bool:
        return self.state == self.State.ACTIVE

    def revoke(self, save: bool = True):
        self.state = self.State.REVOKED
        self.revoked_at = timezone.now()
        if save:
            self.save(update_fields=["state", "revoked_at"])

    def touch(self, save: bool = True):
        """Update last_activity; extend expiry if sliding sessions enabled."""
        self.last_activity = timezone.now()
        fields = ["last_activity"]
        if robust_settings.SLIDING_SESSION:
            try:
                at = self.access_token
                at.expires_at = timezone.now() + timedelta(
                    seconds=robust_settings.SLIDING_SESSION_TTL
                )
                at.save(update_fields=["expires_at"])
                
                # Also slide refresh token to keep them in sync
                try:
                    rt = self.refresh_tokens.filter(
                        is_used=False, is_revoked=False
                    ).first()
                    if rt:
                        rt.expires_at = timezone.now() + timedelta(
                            seconds=robust_settings.REFRESH_TOKEN_TTL
                        )
                        rt.save(update_fields=["expires_at"])
                except Exception:
                    pass  # If refresh token update fails, continue with access token
            except AccessToken.DoesNotExist:
                pass
        if save:
            self.save(update_fields=fields)


# ---------------------------------------------------------------------------
# AccessToken
# ---------------------------------------------------------------------------

class AccessToken(models.Model):
    session = models.OneToOneField(
        Session, on_delete=models.CASCADE, related_name="access_token"
    )
    token_hash = models.CharField(max_length=64, unique=True, db_index=True)
    expires_at = models.DateTimeField(default=_access_expiry)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"AccessToken(session={self.session_id}, expires={self.expires_at})"

    # ------------------------------------------------------------------
    @classmethod
    def create(cls, session: Session) -> tuple["AccessToken", str]:
        """
        Create a new AccessToken for *session*.
        Returns (instance, raw_token).  raw_token is shown ONCE.
        """
        raw = _generate_token()
        token_hash = _hash_token(raw) if robust_settings.HASH_TOKENS else raw
        instance = cls.objects.create(session=session, token_hash=token_hash)
        return instance, raw

    @classmethod
    def authenticate(cls, raw_token: str) -> "AccessToken | None":
        token_hash = _hash_token(raw_token) if robust_settings.HASH_TOKENS else raw_token
        try:
            at = cls.objects.select_related("session__user").get(token_hash=token_hash)
        except cls.DoesNotExist:
            return None
        if at.is_expired() or not at.session.is_active():
            return None
        # Sliding session support
        if robust_settings.SLIDING_SESSION:
            at.session.touch()
        return at

    def is_expired(self) -> bool:
        return timezone.now() >= self.expires_at


# ---------------------------------------------------------------------------
# RefreshToken
# ---------------------------------------------------------------------------

class RefreshToken(models.Model):
    session = models.ForeignKey(
        Session, on_delete=models.CASCADE, related_name="refresh_tokens"
    )
    token_hash = models.CharField(max_length=64, unique=True, db_index=True)
    # Each rotation creates a new token; parent links the chain for reuse detection
    parent = models.OneToOneField(
        "self",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="child",
    )
    family_id = models.UUIDField(default=uuid.uuid4, db_index=True)
    is_used = models.BooleanField(default=False, db_index=True)
    is_revoked = models.BooleanField(default=False, db_index=True)
    expires_at = models.DateTimeField(default=_refresh_expiry)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"RefreshToken(session={self.session_id}, used={self.is_used})"

    # ------------------------------------------------------------------
    @classmethod
    def create(
        cls, session: Session, parent: "RefreshToken | None" = None
    ) -> tuple["RefreshToken", str]:
        raw = _generate_token()
        token_hash = _hash_token(raw) if robust_settings.HASH_TOKENS else raw
        family_id = parent.family_id if parent else uuid.uuid4()
        instance = cls.objects.create(
            session=session,
            token_hash=token_hash,
            parent=parent,
            family_id=family_id,
        )
        return instance, raw

    @classmethod
    def get_valid(cls, raw_token: str) -> "RefreshToken | None":
        token_hash = _hash_token(raw_token) if robust_settings.HASH_TOKENS else raw_token
        try:
            return cls.objects.select_related("session__user").get(
                token_hash=token_hash, is_used=False, is_revoked=False
            )
        except cls.DoesNotExist:
            return None

    def is_expired(self) -> bool:
        return timezone.now() >= self.expires_at

    @transaction.atomic
    def rotate(self) -> tuple["RefreshToken", str]:
        """Mark self used and return a fresh token in the same family.
        
        This operation is atomic — either both the mark and creation succeed,
        or neither do. This prevents leaving a client without a valid token.
        """
        self.is_used = True
        self.save(update_fields=["is_used"])
        return RefreshToken.create(session=self.session, parent=self)

    def revoke_family(self):
        """Revoke every token in this family (reuse-detection response)."""
        RefreshToken.objects.filter(family_id=self.family_id).update(is_revoked=True)


# ---------------------------------------------------------------------------
# LoginHistory
# ---------------------------------------------------------------------------

class LoginHistory(models.Model):
    class EventType(models.TextChoices):
        LOGIN_SUCCESS = "login_success", "Login Success"
        LOGIN_FAILURE = "login_failure", "Login Failure"
        LOGOUT = "logout", "Logout"
        TOKEN_REFRESH = "token_refresh", "Token Refresh"
        TOKEN_REUSE = "token_reuse", "Token Reuse Detected"
        PASSWORD_CHANGE = "password_change", "Password Changed"
        PASSWORD_RESET  = "password_reset",  "Password Reset"
        SESSION_REVOKED = "session_revoked", "Session Revoked"
        FORCED_LOGOUT = "forced_logout", "Forced Logout"

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="robust_auth_history",
        null=True,
        blank=True,
    )
    session = models.ForeignKey(
        Session,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="history",
    )
    event = models.CharField(max_length=32, choices=EventType.choices, db_index=True)

    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, default="")
    extra = models.JSONField(default=dict, blank=True)   # flexible audit payload

    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["user", "event"]),
            models.Index(fields=["user", "timestamp"]),
        ]

    def __str__(self):
        return f"LoginHistory({self.user_id}, {self.event}, {self.timestamp})"