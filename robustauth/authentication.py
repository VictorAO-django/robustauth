"""
DRF authentication class for RobustAuth opaque tokens.

Drop-in replacement for rest_framework.authentication.TokenAuthentication.
"""
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from .models import AccessToken


class RobustTokenAuthentication(BaseAuthentication):
    """
    Authenticate against the RobustAuth AccessToken table.

    Clients must supply the token in the Authorization header::

        Authorization: Bearer <access_token>

    or (legacy compat)::

        Authorization: Token <access_token>
    """

    keyword = "Bearer"
    alt_keyword = "Token"

    def authenticate(self, request):
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        if not auth_header:
            return None

        parts = auth_header.split()
        if len(parts) != 2:
            return None

        prefix, raw_token = parts
        if prefix not in (self.keyword, self.alt_keyword):
            return None

        return self._authenticate_credentials(raw_token)

    def _authenticate_credentials(self, raw_token: str):
        access_token = AccessToken.authenticate(raw_token)

        if access_token is None:
            raise AuthenticationFailed(
                "Invalid or expired access token.", code="token_invalid"
            )

        user = access_token.session.user

        if not user.is_active:
            raise AuthenticationFailed("User account is disabled.", code="user_inactive")

        # Attach session to request for downstream use
        # Access via: request.auth.session
        return user, access_token

    def authenticate_header(self, request):
        return self.keyword


# ---------------------------------------------------------------------------
# drf-spectacular OpenAPI extension
# Teaches Swagger that RobustTokenAuthentication uses Bearer token auth
# ---------------------------------------------------------------------------
try:
    from drf_spectacular.extensions import OpenApiAuthenticationExtension

    class RobustTokenScheme(OpenApiAuthenticationExtension):
        target_class = "robustauth.authentication.RobustTokenAuthentication"
        name = "BearerAuth"

        def get_security_definition(self, auto_schema):
            return {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "opaque",
                "description": (
                    "Opaque access token obtained from POST /auth/login/. "
                    "Format: `Bearer <access_token>`"
                ),
            }

except ImportError:
    pass  