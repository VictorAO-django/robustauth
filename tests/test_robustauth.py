"""
RobustAuth test suite.

Run with: pytest --ds=tests.settings -v
or:        python manage.py test robustauth
"""
import time
from datetime import timedelta
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase
from django.utils import timezone

from robustauth.conf import robust_settings
from robustauth.models import (
    AccessToken,
    LoginHistory,
    RefreshToken,
    Session,
    _hash_token,
)
from robustauth.session_manager import AuthTokenPair, SessionManager

User = get_user_model()


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def make_user(username="testuser", password="testpass123"):
    return User.objects.create_user(username=username, password=password)


def make_session(user=None, **kwargs):
    u = user or make_user(username=f"u_{id(kwargs)}")
    return SessionManager.create_session(u, ip_address="127.0.0.1", user_agent="pytest")


# ---------------------------------------------------------------------------
# Session creation
# ---------------------------------------------------------------------------

class TestCreateSession(TestCase):
    def test_returns_token_pair(self):
        user = make_user()
        pair = SessionManager.create_session(user)
        self.assertIsInstance(pair, AuthTokenPair)
        self.assertTrue(pair.access_token)
        self.assertTrue(pair.refresh_token)
        self.assertIsNotNone(pair.session)

    def test_session_is_active(self):
        user = make_user()
        pair = SessionManager.create_session(user)
        self.assertEqual(pair.session.state, Session.State.ACTIVE)

    def test_access_token_stored_hashed(self):
        user = make_user()
        pair = SessionManager.create_session(user)
        at = AccessToken.objects.get(session=pair.session)
        self.assertEqual(at.token_hash, _hash_token(pair.access_token))

    def test_refresh_token_stored_hashed(self):
        user = make_user()
        pair = SessionManager.create_session(user)
        rt = RefreshToken.objects.get(session=pair.session)
        self.assertEqual(rt.token_hash, _hash_token(pair.refresh_token))

    def test_ip_and_ua_stored(self):
        user = make_user()
        pair = SessionManager.create_session(
            user, ip_address="10.0.0.1", user_agent="TestBrowser/1.0"
        )
        session = pair.session
        self.assertEqual(session.ip_address, "10.0.0.1")
        self.assertEqual(session.user_agent, "TestBrowser/1.0")

    def test_login_history_created(self):
        user = make_user()
        SessionManager.create_session(user)
        self.assertTrue(
            LoginHistory.objects.filter(
                user=user, event=LoginHistory.EventType.LOGIN_SUCCESS
            ).exists()
        )


# ---------------------------------------------------------------------------
# Session policy: single
# ---------------------------------------------------------------------------

class TestSessionPolicySingle(TestCase):
    def test_single_policy_revokes_existing(self):
        from django.test import override_settings
        with override_settings(ROBUST_AUTH={"SESSION_POLICY": "single", "HASH_TOKENS": True,
                                            "STORE_LOGIN_HISTORY": True, "STORE_LOGOUT_HISTORY": True,
                                            "TRACK_IPS": True, "TRACK_USER_AGENTS": True}):
            # Re-init settings proxy to pick up override
            from robustauth import conf
            conf.robust_settings._user = {"SESSION_POLICY": "single", "HASH_TOKENS": True,
                                          "STORE_LOGIN_HISTORY": True, "STORE_LOGOUT_HISTORY": True,
                                          "TRACK_IPS": True, "TRACK_USER_AGENTS": True}
            user = make_user(username="single_user")
            pair1 = SessionManager.create_session(user)
            pair2 = SessionManager.create_session(user)
            pair1.session.refresh_from_db()
            self.assertEqual(pair1.session.state, Session.State.REVOKED)
            self.assertEqual(pair2.session.state, Session.State.ACTIVE)
            # Restore defaults
            conf.robust_settings._user = getattr(__import__("django.conf", fromlist=["settings"]).settings, "ROBUST_AUTH", {})


# ---------------------------------------------------------------------------
# Session policy: max_count
# ---------------------------------------------------------------------------

class TestSessionPolicyMaxCount(TestCase):
    def test_max_count_revokes_oldest(self):
        from robustauth import conf
        conf.robust_settings._user = {
            "SESSION_POLICY": "max_count", "MAX_SESSIONS": 2,
            "REVOKE_OLDEST_ON_LIMIT": True, "HASH_TOKENS": True,
            "STORE_LOGIN_HISTORY": True, "STORE_LOGOUT_HISTORY": True,
            "TRACK_IPS": True, "TRACK_USER_AGENTS": True,
        }
        user = make_user(username="max_count_user")
        pair1 = SessionManager.create_session(user)
        pair2 = SessionManager.create_session(user)
        pair3 = SessionManager.create_session(user)   # pushes pair1 out
        pair1.session.refresh_from_db()
        self.assertEqual(pair1.session.state, Session.State.REVOKED)
        self.assertEqual(Session.objects.filter(user=user, state=Session.State.ACTIVE).count(), 2)
        # Restore defaults
        from django.conf import settings as dj_settings
        conf.robust_settings._user = getattr(dj_settings, "ROBUST_AUTH", {})


# ---------------------------------------------------------------------------
# AccessToken authentication
# ---------------------------------------------------------------------------

class TestAccessTokenAuthentication(TestCase):
    def test_valid_token_authenticates(self):
        user = make_user()
        pair = SessionManager.create_session(user)
        at = AccessToken.authenticate(pair.access_token)
        self.assertIsNotNone(at)
        self.assertEqual(at.session.user, user)

    def test_wrong_token_returns_none(self):
        at = AccessToken.authenticate("completely_wrong_token")
        self.assertIsNone(at)

    def test_expired_token_returns_none(self):
        user = make_user()
        pair = SessionManager.create_session(user)
        # Manually expire the token
        AccessToken.objects.filter(session=pair.session).update(
            expires_at=timezone.now() - timedelta(seconds=1)
        )
        at = AccessToken.authenticate(pair.access_token)
        self.assertIsNone(at)

    def test_revoked_session_rejects_token(self):
        user = make_user()
        pair = SessionManager.create_session(user)
        pair.session.revoke()
        at = AccessToken.authenticate(pair.access_token)
        self.assertIsNone(at)


# ---------------------------------------------------------------------------
# Refresh token rotation
# ---------------------------------------------------------------------------

class TestRefreshTokenRotation(TestCase):
    def test_refresh_issues_new_tokens(self):
        user = make_user()
        pair1 = SessionManager.create_session(user)
        pair2 = SessionManager.refresh_session(pair1.refresh_token)
        self.assertNotEqual(pair1.access_token, pair2.access_token)
        self.assertNotEqual(pair1.refresh_token, pair2.refresh_token)

    def test_old_refresh_token_marked_used(self):
        user = make_user()
        pair = SessionManager.create_session(user)
        SessionManager.refresh_session(pair.refresh_token)
        rt = RefreshToken.objects.get(token_hash=_hash_token(pair.refresh_token))
        self.assertTrue(rt.is_used)

    def test_reused_refresh_token_revokes_family(self):
        user = make_user()
        pair = SessionManager.create_session(user)
        SessionManager.refresh_session(pair.refresh_token)   # legit use
        # Attempt to reuse the original (now-used) token
        with self.assertRaises(ValueError):
            SessionManager.refresh_session(pair.refresh_token)
        # All sessions should be revoked
        active = Session.objects.filter(user=user, state=Session.State.ACTIVE)
        self.assertEqual(active.count(), 0)

    def test_expired_refresh_token_raises(self):
        user = make_user()
        pair = SessionManager.create_session(user)
        RefreshToken.objects.filter(session=pair.session).update(
            expires_at=timezone.now() - timedelta(seconds=1)
        )
        with self.assertRaises(ValueError):
            SessionManager.refresh_session(pair.refresh_token)

    def test_new_access_token_authenticates(self):
        user = make_user()
        pair1 = SessionManager.create_session(user)
        pair2 = SessionManager.refresh_session(pair1.refresh_token)
        at = AccessToken.authenticate(pair2.access_token)
        self.assertIsNotNone(at)
        self.assertEqual(at.session.user, user)

    def test_old_access_token_no_longer_valid_after_refresh(self):
        user = make_user()
        pair1 = SessionManager.create_session(user)
        SessionManager.refresh_session(pair1.refresh_token)
        # Old access token should no longer be valid
        at = AccessToken.authenticate(pair1.access_token)
        self.assertIsNone(at)


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

class TestLogout(TestCase):
    def test_logout_revokes_session(self):
        user = make_user()
        pair = SessionManager.create_session(user)
        SessionManager.logout_session(pair.session)
        pair.session.refresh_from_db()
        self.assertEqual(pair.session.state, Session.State.REVOKED)

    def test_logout_invalidates_access_token(self):
        user = make_user()
        pair = SessionManager.create_session(user)
        SessionManager.logout_session(pair.session)
        at = AccessToken.authenticate(pair.access_token)
        self.assertIsNone(at)

    def test_logout_all_revokes_all_sessions(self):
        user = make_user()
        pair1 = SessionManager.create_session(user)
        pair2 = SessionManager.create_session(user)
        SessionManager.logout_all_sessions(user)
        for pair in (pair1, pair2):
            pair.session.refresh_from_db()
            self.assertEqual(pair.session.state, Session.State.REVOKED)

    def test_logout_all_except_current(self):
        user = make_user()
        pair1 = SessionManager.create_session(user)
        pair2 = SessionManager.create_session(user)
        SessionManager.logout_all_sessions(user, except_session=pair2.session)
        pair1.session.refresh_from_db()
        pair2.session.refresh_from_db()
        self.assertEqual(pair1.session.state, Session.State.REVOKED)
        self.assertEqual(pair2.session.state, Session.State.ACTIVE)


# ---------------------------------------------------------------------------
# Password change
# ---------------------------------------------------------------------------

class TestPasswordChange(TestCase):
    def test_password_change_revokes_other_sessions(self):
        user = make_user()
        pair1 = SessionManager.create_session(user)
        pair2 = SessionManager.create_session(user)
        SessionManager.on_password_change(user, current_session=pair2.session)
        pair1.session.refresh_from_db()
        pair2.session.refresh_from_db()
        self.assertEqual(pair1.session.state, Session.State.REVOKED)
        self.assertEqual(pair2.session.state, Session.State.ACTIVE)


# ---------------------------------------------------------------------------
# Login history
# ---------------------------------------------------------------------------

class TestLoginHistory(TestCase):
    def test_login_success_logged(self):
        user = make_user()
        SessionManager.create_session(user)
        self.assertTrue(
            LoginHistory.objects.filter(user=user, event="login_success").exists()
        )

    def test_logout_logged(self):
        user = make_user()
        pair = SessionManager.create_session(user)
        SessionManager.logout_session(pair.session)
        self.assertTrue(
            LoginHistory.objects.filter(user=user, event="logout").exists()
        )

    def test_token_refresh_logged(self):
        user = make_user()
        pair = SessionManager.create_session(user)
        SessionManager.refresh_session(pair.refresh_token)
        self.assertTrue(
            LoginHistory.objects.filter(user=user, event="token_refresh").exists()
        )


# ---------------------------------------------------------------------------
# DRF authentication backend
# ---------------------------------------------------------------------------

class TestRobustTokenAuthentication(TestCase):
    def setUp(self):
        from robustauth.authentication import RobustTokenAuthentication
        self.auth = RobustTokenAuthentication()
        self.factory = RequestFactory()

    def _make_request(self, token, prefix="Bearer"):
        request = self.factory.get("/")
        request.META["HTTP_AUTHORIZATION"] = f"{prefix} {token}"
        return request

    def test_valid_bearer_token(self):
        user = make_user()
        pair = SessionManager.create_session(user)
        request = self._make_request(pair.access_token)
        result = self.auth.authenticate(request)
        self.assertIsNotNone(result)
        auth_user, at = result
        self.assertEqual(auth_user, user)

    def test_legacy_token_prefix(self):
        user = make_user()
        pair = SessionManager.create_session(user)
        request = self._make_request(pair.access_token, prefix="Token")
        result = self.auth.authenticate(request)
        self.assertIsNotNone(result)

    def test_invalid_token_raises(self):
        from rest_framework.exceptions import AuthenticationFailed
        request = self._make_request("invalid_token_xyz")
        with self.assertRaises(AuthenticationFailed):
            self.auth.authenticate(request)

    def test_no_auth_header_returns_none(self):
        request = self.factory.get("/")
        result = self.auth.authenticate(request)
        self.assertIsNone(result)

    def test_malformed_header_returns_none(self):
        request = self.factory.get("/")
        request.META["HTTP_AUTHORIZATION"] = "BearerOnlyOneWord"
        result = self.auth.authenticate(request)
        self.assertIsNone(result)