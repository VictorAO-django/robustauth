"""
RobustAuth signals.

Connect to these in your own apps for hooks, alerting, or custom logic.

Example::

    from robust_auth import signals

    @receiver(signals.token_reuse_detected)
    def alert_security_team(sender, user, session, ip_address, **kwargs):
        SecurityAlert.objects.create(user=user, ip=ip_address, kind="token_reuse")
"""
from django.dispatch import Signal

# Fired after a new session is created (successful login)
user_logged_in = Signal()   # kwargs: user, session

# Fired when a session is revoked (any logout path)
user_logged_out = Signal()  # kwargs: user, session

# Fired when a refresh token that has already been used is presented again.
# All sessions are force-revoked when this fires.
token_reuse_detected = Signal()  # kwargs: user, session, ip_address

# Fired when a user hits MAX_SESSIONS and REVOKE_OLDEST_ON_LIMIT=False
session_limit_reached = Signal()  # kwargs: user, active_sessions

# Fired when failed login threshold is breached
brute_force_threshold_hit = Signal()  # kwargs: username, ip_address, failure_count

# Fired after password change (other sessions revoked, current session token refreshed)
password_changed = Signal()  # kwargs: user, current_session, new_pair (AuthTokenPair | None)

# Fired after password reset (all sessions revoked by default)
password_reset = Signal()    # kwargs: user, new_pair (AuthTokenPair | None)