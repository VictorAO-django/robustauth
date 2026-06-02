"""
SessionManager: the central service layer for RobustAuth.

All business logic for creating, validating, rotating, and revoking
sessions lives here so views/serializers stay thin.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from django.db import transaction
from django.utils import timezone

from . import signals
from .conf import robust_settings
from .models import AccessToken, LoginHistory, RefreshToken, Session

if TYPE_CHECKING:
    from django.contrib.auth.models import AbstractUser


class AuthTokenPair:
    """Value object returned after a successful login or refresh."""

    __slots__ = ("access_token", "refresh_token", "session")

    def __init__(self, access_token: str, refresh_token: str, session: Session):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.session = session


class SessionManager:
    # ------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------

    @classmethod
    @transaction.atomic
    def create_session(
        cls,
        user: AbstractUser,
        *,
        ip_address: str | None = None,
        user_agent: str = "",
        extra: dict | None = None,
    ) -> AuthTokenPair:
        """
        Create a new session for *user* honouring the configured SESSION_POLICY.
        Returns an AuthTokenPair with raw (plaintext) tokens.
        
        This method is fully atomic — all database operations succeed or fail together.
        """
        cls._enforce_session_policy(user)

        device_info = cls._parse_device(user_agent)

        session = Session.objects.create(
            user=user,
            ip_address=ip_address if robust_settings.TRACK_IPS else None,
            user_agent=user_agent if robust_settings.TRACK_USER_AGENTS else "",
            **device_info,
        )

        access_obj, raw_access = AccessToken.create(session)
        refresh_obj, raw_refresh = RefreshToken.create(session)

        if robust_settings.STORE_LOGIN_HISTORY:
            cls._log(
                user=user,
                session=session,
                event=LoginHistory.EventType.LOGIN_SUCCESS,
                ip_address=ip_address,
                user_agent=user_agent,
                extra=extra or {},
            )

        signals.user_logged_in.send(
            sender=user.__class__, user=user, session=session
        )

        return AuthTokenPair(
            access_token=raw_access,
            refresh_token=raw_refresh,
            session=session,
        )

    # ------------------------------------------------------------------
    # Refresh
    # ------------------------------------------------------------------

    @classmethod
    def refresh_session(
        cls,
        raw_refresh_token: str,
        *,
        ip_address: str | None = None,
        user_agent: str = "",
    ) -> AuthTokenPair:
        """
        Validate *raw_refresh_token* and return a new AuthTokenPair.
        
        This method is atomic for the happy path. Reuse detection is atomic separately
        to ensure security events persist even if the refresh fails.
        Raises ValueError on any invalid / expired / reused condition.
        """
        # Handle reuse detection OUTSIDE the atomic block for refresh,
        # so reuse actions persist even if refresh_session raises
        rt = RefreshToken.get_valid(raw_refresh_token)

        if rt is None:
            # Could be a reuse attempt — check if the token exists but is used
            # This transaction is SEPARATE from the refresh transaction
            with transaction.atomic():
                cls._handle_possible_reuse(raw_refresh_token, ip_address, user_agent)
            raise ValueError("Invalid or expired refresh token.")
        
        # Now do the actual refresh in an atomic transaction
        return cls._refresh_session_atomic(rt, ip_address, user_agent)

    @classmethod
    @transaction.atomic
    def _refresh_session_atomic(
        cls,
        rt: RefreshToken,
        ip_address: str | None = None,
        user_agent: str = "",
    ) -> AuthTokenPair:
        """Atomic refresh operation. Called after token is validated."""
        rt = RefreshToken.objects.select_related("session__user").get(pk=rt.pk)

        if rt.is_expired():
            raise ValueError("Refresh token has expired.")

        if not rt.session.is_active():
            raise ValueError("Session is no longer active.")

        session = rt.session
        user = session.user

        # Rotate refresh token
        new_rt_obj, raw_new_refresh = rt.rotate()

        # Replace access token
        AccessToken.objects.filter(session=session).delete()
        _, raw_new_access = AccessToken.create(session)

        # Update session activity
        session.last_activity = timezone.now()
        fields = ["last_activity"]
        if robust_settings.TRACK_IPS and ip_address:
            session.ip_address = ip_address
            fields.append("ip_address")
        session.save(update_fields=fields)

        if robust_settings.STORE_LOGIN_HISTORY:
            cls._log(
                user=user,
                session=session,
                event=LoginHistory.EventType.TOKEN_REFRESH,
                ip_address=ip_address,
                user_agent=user_agent,
            )

        return AuthTokenPair(
            access_token=raw_new_access,
            refresh_token=raw_new_refresh,
            session=session,
        )

    # ------------------------------------------------------------------
    # Logout
    # ------------------------------------------------------------------

    @classmethod
    def logout_session(
        cls,
        session: Session,
        *,
        ip_address: str | None = None,
        user_agent: str = "",
        event: str = LoginHistory.EventType.LOGOUT,
    ) -> None:
        session.revoke()
        AccessToken.objects.filter(session=session).delete()
        RefreshToken.objects.filter(session=session, is_used=False).update(
            is_revoked=True
        )

        if robust_settings.STORE_LOGOUT_HISTORY:
            cls._log(
                user=session.user,
                session=session,
                event=event,
                ip_address=ip_address,
                user_agent=user_agent,
            )

        signals.user_logged_out.send(
            sender=session.user.__class__, user=session.user, session=session
        )

    @classmethod
    def logout_all_sessions(
        cls,
        user: AbstractUser,
        *,
        except_session: Session | None = None,
        ip_address: str | None = None,
        event: str = LoginHistory.EventType.FORCED_LOGOUT,
    ) -> int:
        """Revoke all active sessions. Returns count revoked."""
        return cls._logout_all_sessions_batch(
            user,
            except_session=except_session,
            ip_address=ip_address,
            event=event,
        )

    @classmethod
    def _logout_all_sessions_batch(
        cls,
        user: AbstractUser,
        *,
        except_session: Session | None = None,
        ip_address: str | None = None,
        event: str = LoginHistory.EventType.FORCED_LOGOUT,
    ) -> int:
        """
        Revoke all active sessions using batch operations to avoid N+1 queries.
        Returns count revoked.
        """
        qs = Session.objects.filter(user=user, state=Session.State.ACTIVE)
        if except_session:
            qs = qs.exclude(pk=except_session.pk)

        session_list = list(qs)
        if not session_list:
            return 0

        session_ids = [s.id for s in session_list]

        # Batch revoke sessions
        Session.objects.filter(id__in=session_ids).update(
            state=Session.State.REVOKED,
            revoked_at=timezone.now(),
        )

        # Batch delete access tokens
        AccessToken.objects.filter(session_id__in=session_ids).delete()

        # Batch revoke unused refresh tokens
        RefreshToken.objects.filter(
            session_id__in=session_ids, is_used=False
        ).update(is_revoked=True)

        # Log events for each session
        if robust_settings.STORE_LOGOUT_HISTORY:
            for session in session_list:
                cls._log(
                    user=session.user,
                    session=session,
                    event=event,
                    ip_address=ip_address,
                    user_agent="",
                )

        # Send signals for each session
        for session in session_list:
            signals.user_logged_out.send(
                sender=user.__class__, user=user, session=session
            )

        return len(session_list)

    # ------------------------------------------------------------------
    # Password change / reset hooks
    # ------------------------------------------------------------------

    @classmethod
    def on_password_change(
        cls,
        user: AbstractUser,
        *,
        current_session: Session | None = None,
    ) -> AuthTokenPair | None:
        """
        Call this after a user successfully changes their password.

        Behaviour controlled by settings:
        - REVOKE_ON_PASSWORD_CHANGE      : revoke all OTHER sessions (default True)
        - REFRESH_TOKEN_ON_PASSWORD_CHANGE: issue a fresh token pair to the current
                                            session so the client doesn't get logged
                                            out mid-session (default True)

        Returns a new AuthTokenPair for the current session if
        REFRESH_TOKEN_ON_PASSWORD_CHANGE is True and current_session is provided,
        otherwise returns None.
        """
        # 1. Revoke all other sessions
        if robust_settings.REVOKE_ON_PASSWORD_CHANGE:
            cls.logout_all_sessions(
                user,
                except_session=current_session,
                event=LoginHistory.EventType.PASSWORD_CHANGE,
            )

        # 2. Log the event against the current session
        cls._log(
            user=user,
            session=current_session,
            event=LoginHistory.EventType.PASSWORD_CHANGE,
        )

        # 3. Issue a fresh token pair to the current session so the
        #    client stays logged in with new credentials
        new_pair = None
        if robust_settings.REFRESH_TOKEN_ON_PASSWORD_CHANGE and current_session:
            new_pair = cls._reissue_tokens(current_session)

        signals.password_changed.send(
            sender=user.__class__,
            user=user,
            current_session=current_session,
            new_pair=new_pair,
        )
        return new_pair

    @classmethod
    def on_password_reset(
        cls,
        user: AbstractUser,
        *,
        current_session: Session | None = None,
    ) -> AuthTokenPair | None:
        """
        Call this after a password reset flow completes (e.g. reset-via-email link).

        Behaviour controlled by settings:
        - REVOKE_ON_PASSWORD_RESET       : revoke ALL sessions including current
                                            (default True — password reset is a
                                            stronger security event than a change)
        - REFRESH_TOKEN_ON_PASSWORD_RESET: issue a new token pair after reset so
                                            the user is immediately logged in
                                            (default False — force re-login instead)

        Returns a new AuthTokenPair if REFRESH_TOKEN_ON_PASSWORD_RESET is True,
        otherwise returns None (client must login again).
        """
        # 1. Revoke ALL sessions — including current — on reset by default.
        #    Password reset = someone used an out-of-band link; treat as
        #    potentially compromised until they re-authenticate.
        if robust_settings.REVOKE_ON_PASSWORD_RESET:
            cls._logout_all_sessions_batch(
                user,
                except_session=None,  # no exceptions — revoke everything
                event=LoginHistory.EventType.PASSWORD_RESET,
            )

        # 2. Log the reset event
        cls._log(
            user=user,
            session=current_session,
            event=LoginHistory.EventType.PASSWORD_RESET,
        )

        # 3. Optionally issue a fresh session so the user lands logged in
        #    right after the reset form (only if configured).
        #    We create it directly with proper device info to avoid policy checks.
        new_pair = None
        if robust_settings.REFRESH_TOKEN_ON_PASSWORD_RESET:
            # Create session directly since all old sessions were revoked
            new_session = Session.objects.create(user=user)
            new_pair = cls._reissue_tokens(new_session)

        signals.password_reset.send(
            sender=user.__class__,
            user=user,
            new_pair=new_pair,
        )
        return new_pair

    @classmethod
    def _reissue_tokens(cls, session: Session) -> AuthTokenPair:
        """Replace access + refresh tokens on an existing session and return the new pair."""
        AccessToken.objects.filter(session=session).delete()
        RefreshToken.objects.filter(session=session, is_used=False).update(is_revoked=True)

        _, raw_access  = AccessToken.create(session)
        _, raw_refresh = RefreshToken.create(session)

        return AuthTokenPair(
            access_token=raw_access,
            refresh_token=raw_refresh,
            session=session,
        )

    # ------------------------------------------------------------------
    # Session policy enforcement
    # ------------------------------------------------------------------

    @classmethod
    def _enforce_session_policy(cls, user: AbstractUser) -> None:
        """
        Enforce the configured session policy with proper atomicity.
        Uses select_for_update() to prevent race conditions.
        """
        policy = robust_settings.SESSION_POLICY
        # Lock all active sessions for this user to prevent concurrent modifications
        active = list(
            Session.objects.select_for_update().filter(
                user=user, state=Session.State.ACTIVE
            ).order_by("created_at")
        )

        if policy == "single":
            for s in active:
                cls.logout_session(s, event=LoginHistory.EventType.FORCED_LOGOUT)

        elif policy == "max_count":
            max_s = robust_settings.MAX_SESSIONS
            overflow = len(active) - max_s + 1  # +1 for the one we're about to create
            if overflow > 0:
                if robust_settings.REVOKE_OLDEST_ON_LIMIT:
                    for s in active[:overflow]:
                        cls.logout_session(s, event=LoginHistory.EventType.FORCED_LOGOUT)
                else:
                    signals.session_limit_reached.send(
                        sender=user.__class__, user=user, active_sessions=active
                    )
                    raise ValueError(
                        f"Maximum session limit ({max_s}) reached. "
                        "Please log out from another device."
                    )
        # "multi" → no restrictions

    # ------------------------------------------------------------------
    # Reuse detection
    # ------------------------------------------------------------------

    @classmethod
    def _handle_possible_reuse(
        cls, raw_token: str, ip_address: str | None, user_agent: str
    ) -> None:
        """
        Detect and respond to token reuse attempts.
        
        A reused token indicates a potential security breach (token compromised).
        We revoke the entire token family to prevent continued exploitation.
        """
        from .models import _hash_token

        token_hash = _hash_token(raw_token) if robust_settings.HASH_TOKENS else raw_token
        
        try:
            rt = RefreshToken.objects.select_related("session__user").get(
                token_hash=token_hash
            )
        except RefreshToken.DoesNotExist:
            return

        if not robust_settings.REFRESH_TOKEN_REUSE_DETECTION:
            return
        
        # Verify it's actually a reuse: token exists but is already used or revoked
        # This indicates the token has been used before and someone is trying to use it again
        if not (rt.is_used or rt.is_revoked):
            # Token is still valid and hasn't been used, not a reuse attempt
            return
        
        # Check if family already revoked to avoid duplicate logging
        if rt.is_revoked and RefreshToken.objects.filter(
            family_id=rt.family_id, is_revoked=False
        ).exists():
            # Family not fully revoked yet, this is the reuse detection
            pass
        elif rt.is_revoked:
            # Already revoked, skip
            return

        user = rt.session.user
        rt.revoke_family()
        cls._logout_all_sessions_batch(user, event=LoginHistory.EventType.SESSION_REVOKED)

        cls._log(
            user=user,
            session=rt.session,
            event=LoginHistory.EventType.TOKEN_REUSE,
            ip_address=ip_address,
            user_agent=user_agent,
            extra={"token_family": str(rt.family_id)},
        )

        signals.token_reuse_detected.send(
            sender=user.__class__,
            user=user,
            session=rt.session,
            ip_address=ip_address,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_device(user_agent: str) -> dict:
        """
        Parse device/browser/OS information from user agent string.
        
        Returns a dict with all device_* keys to ensure consistent Session fields.
        """
        # Always return complete dict, even if tracking is disabled
        default_device_info = {
            "device_type": "",
            "os_family": "",
            "browser_family": "",
            "device_name": "",
        }
        
        if not robust_settings.TRACK_DEVICE_INFO or not user_agent:
            return default_device_info
        
        try:
            from user_agents import parse as ua_parse  # type: ignore[import-not-found]

            ua = ua_parse(user_agent)
            return {
                "device_type": (
                    "mobile"
                    if ua.is_mobile
                    else "tablet"
                    if ua.is_tablet
                    else "desktop"
                ),
                "os_family": ua.os.family,
                "browser_family": ua.browser.family,
                "device_name": ua.device.family,
            }
        except (ImportError, Exception):
            # If parsing fails or library not installed, return defaults
            return default_device_info

    @staticmethod
    def _log(
        *,
        user,
        session,
        event: str,
        ip_address: str | None = None,
        user_agent: str = "",
        extra: dict | None = None,
    ) -> None:
        LoginHistory.objects.create(
            user=user,
            session=session,
            event=event,
            ip_address=ip_address,
            user_agent=user_agent,
            extra=extra or {},
        )