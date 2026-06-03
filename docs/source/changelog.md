# Changelog

All notable changes to RobustAuth will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.1.1] - 2026-06-03

### Fixed
- Corrected default `LOGIN_SERIALIZER` path from `robust_auth.serializers.UsernameLoginSerializer` to `robustauth.serializers.UsernameLoginSerializer`

---

## [0.1.0] - 2026-06-03

### Added
- Opaque token authentication with SHA-256 hashed storage
- Short-lived access tokens with configurable TTL
- Refresh token rotation — old token invalidated on every use
- Refresh token reuse detection with full family revocation
- Session model with UUID primary key and state tracking (`active`, `revoked`, `expired`)
- Session policies: `single`, `multi`, `max_count`
- Automatic oldest-session revocation when `MAX_SESSIONS` limit is hit
- Device and browser fingerprinting via optional `user-agents` library
- IP address and User-Agent tracking per session
- Login history audit log (`login_success`, `login_failure`, `logout`, `token_refresh`, `token_reuse`, `password_change`, `session_revoked`, `forced_logout`)
- Brute-force protection via configurable failure threshold and signals
- Automatic session revocation on password change
- Sliding session support with configurable inactivity TTL
- `RobustTokenAuthentication` DRF backend (`Bearer` and legacy `Token` prefix)
- `RobustAuthMiddleware` attaching `request.robust_session` to all requests
- 7 REST API endpoints: login, refresh, logout, logout-all, sessions list, session revoke, login history
- Django admin integration with session revocation action
- 5 extensibility signals: `user_logged_in`, `user_logged_out`, `token_reuse_detected`, `session_limit_reached`, `brute_force_threshold_hit`
- `robustauth_cleanup` management command with `--dry-run` support
- Initial migration
- Full test suite (31 tests)
- PyPI packaging via `pyproject.toml`

[Unreleased]: https://github.com/VictorAO-django/robustauth/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/VictorAO-django/robustauth/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/VictorAO-django/robustauth/releases/tag/v0.1.0