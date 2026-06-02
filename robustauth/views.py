"""
DRF API views for RobustAuth.
Documented for drf-spectacular (OpenAPI 3).
"""
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView

from drf_spectacular.utils import (
    extend_schema,
    extend_schema_view,
    OpenApiParameter,
    OpenApiExample,
    OpenApiResponse,
    inline_serializer,
)
from drf_spectacular.types import OpenApiTypes
from rest_framework import serializers as drf_serializers

from django.utils.module_loading import import_string

from .authentication import RobustTokenAuthentication
from .conf import robust_settings
from .models import LoginHistory, Session
from .serializers import (
    LoginHistorySerializer,
    LogoutAllSerializer,
    LogoutSerializer,
    RefreshTokenSerializer,
    SessionSerializer,
)
from .session_manager import SessionManager


def _get_login_serializer_class():
    """Load LOGIN_SERIALIZER from settings — allows full customisation."""
    return import_string(robust_settings.LOGIN_SERIALIZER)


# ---------------------------------------------------------------------------
# Reusable inline response serializers for Swagger docs
# ---------------------------------------------------------------------------

_TokenPairResponse = inline_serializer(
    name="TokenPairResponse",
    fields={
        "access_token": drf_serializers.CharField(help_text="Short-lived opaque access token. Send as: Authorization: Bearer <token>"),
        "refresh_token": drf_serializers.CharField(help_text="Long-lived token used to obtain new access tokens."),
        "session_id": drf_serializers.UUIDField(help_text="UUID of the created session."),
        "token_type": drf_serializers.CharField(help_text="Always 'Bearer'."),
    },
)

_RefreshResponse = inline_serializer(
    name="RefreshResponse",
    fields={
        "access_token": drf_serializers.CharField(help_text="New access token."),
        "refresh_token": drf_serializers.CharField(help_text="New refresh token. The old one is now invalid."),
        "token_type": drf_serializers.CharField(help_text="Always 'Bearer'."),
    },
)

_DetailResponse = inline_serializer(
    name="DetailResponse",
    fields={
        "detail": drf_serializers.CharField(help_text="Human-readable result message."),
    },
)

_ErrorResponse = inline_serializer(
    name="ErrorResponse",
    fields={
        "non_field_errors": drf_serializers.ListField(
            child=drf_serializers.CharField(),
            help_text="List of error messages.",
        ),
    },
)


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------

class LoginView(APIView):
    authentication_classes = []
    permission_classes = []

    @extend_schema(
        # tags=["Authentication"],
        summary="Login",
        description=(
            "Authenticate with username and password. "
            "Returns a short-lived **access token** and a long-lived **refresh token**.\n\n"
            "Use the access token in the `Authorization: Bearer <token>` header for all protected endpoints.\n\n"
            "When the access token expires, use `/auth/token/refresh/` to get a new pair — "
            "the refresh token is rotated on every use."
        ),
        request=_get_login_serializer_class(),
        responses={
            200: OpenApiResponse(
                response=_TokenPairResponse,
                description="Login successful. Returns token pair.",
                examples=[
                    OpenApiExample(
                        "Success",
                        value={
                            "access_token": "a3f9c2d1e4b5...",
                            "refresh_token": "b7c241f5a8d9...",
                            "session_id": "550e8400-e29b-41d4-a716-446655440000",
                            "token_type": "Bearer",
                        },
                    )
                ],
            ),
            400: OpenApiResponse(
                response=_ErrorResponse,
                description="Invalid credentials or inactive account.",
                examples=[
                    OpenApiExample(
                        "Invalid credentials",
                        value={"non_field_errors": ["Invalid credentials."]},
                    ),
                    OpenApiExample(
                        "Session limit reached",
                        value={"non_field_errors": ["Maximum session limit (5) reached. Please log out from another device."]},
                    ),
                ],
            ),
        },
    )
    def get_serializer_class(self):
        return _get_login_serializer_class()

    def post(self, request):
        serializer_class = self.get_serializer_class()
        serializer = serializer_class(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.to_representation(None), status=status.HTTP_200_OK)


class RefreshView(APIView):
    authentication_classes = []
    permission_classes = []

    @extend_schema(
        # tags=["Authentication"],
        summary="Refresh access token",
        description=(
            "Exchange a valid refresh token for a **new access + refresh token pair**.\n\n"
            "The submitted refresh token is immediately invalidated after use — "
            "store the new one for the next refresh.\n\n"
            "**Security:** If an already-used refresh token is submitted, RobustAuth detects "
            "the reuse, revokes the entire token family, and terminates all sessions for that user."
        ),
        request=RefreshTokenSerializer,
        responses={
            200: OpenApiResponse(
                response=_RefreshResponse,
                description="New token pair issued.",
                examples=[
                    OpenApiExample(
                        "Success",
                        value={
                            "access_token": "d1e4f5c2a3b9...",
                            "refresh_token": "f5a8b9c2d1e4...",
                            "token_type": "Bearer",
                        },
                    )
                ],
            ),
            400: OpenApiResponse(
                response=_ErrorResponse,
                description="Invalid, expired, or already-used refresh token.",
                examples=[
                    OpenApiExample(
                        "Expired",
                        value={"non_field_errors": ["Refresh token has expired."]},
                    ),
                    OpenApiExample(
                        "Invalid",
                        value={"non_field_errors": ["Invalid or expired refresh token."]},
                    ),
                ],
            ),
        },
    )
    def post(self, request):
        serializer = RefreshTokenSerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.to_representation(None), status=status.HTTP_200_OK)


class LogoutView(APIView):
    authentication_classes = [RobustTokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        # tags=["Authentication"],
        summary="Logout",
        description=(
            "Revoke the **current session**. The access token and all associated "
            "refresh tokens are immediately invalidated.\n\n"
            "Requires `Authorization: Bearer <access_token>` header."
        ),
        request=None,
        responses={
            200: OpenApiResponse(
                response=_DetailResponse,
                description="Logged out successfully.",
                examples=[
                    OpenApiExample(
                        "Success",
                        value={"detail": "Logged out successfully."},
                    )
                ],
            ),
            401: OpenApiResponse(description="Missing or invalid access token."),
        },
    )
    def post(self, request):
        session = request.auth.session
        from .serializers import _get_client_ip
        SessionManager.logout_session(
            session,
            ip_address=_get_client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
        )
        return Response({"detail": "Logged out successfully."}, status=status.HTTP_200_OK)


class LogoutAllView(APIView):
    authentication_classes = [RobustTokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        # tags=["Authentication"],
        summary="Logout all sessions",
        description=(
            "Revoke **all active sessions** for the authenticated user.\n\n"
            "Set `keep_current: true` to keep the current session alive and only "
            "revoke all other devices. Set `keep_current: false` to log out everywhere, "
            "including the current session.\n\n"
            "Useful for 'Sign out all other devices' functionality."
        ),
        request=LogoutAllSerializer,
        responses={
            200: OpenApiResponse(
                response=_DetailResponse,
                description="Sessions revoked.",
                examples=[
                    OpenApiExample(
                        "Revoked others",
                        value={"detail": "Revoked 2 session(s)."},
                    ),
                    OpenApiExample(
                        "Revoked all",
                        value={"detail": "Revoked 3 session(s)."},
                    ),
                ],
            ),
            401: OpenApiResponse(description="Missing or invalid access token."),
        },
    )
    def post(self, request):
        serializer = LogoutAllSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        keep_current = serializer.validated_data["keep_current"]
        current_session = request.auth.session

        from .serializers import _get_client_ip
        count = SessionManager.logout_all_sessions(
            request.user,
            except_session=current_session if keep_current else None,
            ip_address=_get_client_ip(request),
        )
        return Response(
            {"detail": f"Revoked {count} session(s)."},
            status=status.HTTP_200_OK,
        )


@extend_schema_view(
    list=extend_schema(
        # tags=["Sessions"],
        summary="List active sessions",
        description=(
            "Returns all **active sessions** for the authenticated user, "
            "ordered by most recent first.\n\n"
            "The current session is identified with `is_current: true`. "
            "Each session includes device, browser, OS, and IP information "
            "(if tracking is enabled in settings).\n\n"
            "Use this to build a 'Manage devices' screen."
        ),
        responses={
            200: OpenApiResponse(
                response=SessionSerializer(many=True),
                description="List of active sessions.",
                examples=[
                    OpenApiExample(
                        "Two active sessions",
                        value=[
                            {
                                "id": "550e8400-e29b-41d4-a716-446655440000",
                                "state": "active",
                                "ip_address": "41.58.12.34",
                                "device_type": "mobile",
                                "os_family": "Android",
                                "browser_family": "Chrome Mobile",
                                "device_name": "Samsung SM-G991",
                                "created_at": "2025-06-01T10:23:00Z",
                                "last_activity": "2025-06-01T14:05:00Z",
                                "is_current": True,
                            },
                            {
                                "id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
                                "state": "active",
                                "ip_address": "41.58.12.34",
                                "device_type": "desktop",
                                "os_family": "Windows",
                                "browser_family": "Firefox",
                                "device_name": "Other",
                                "created_at": "2025-05-30T08:00:00Z",
                                "last_activity": "2025-05-30T09:15:00Z",
                                "is_current": False,
                            },
                        ],
                    )
                ],
            ),
            401: OpenApiResponse(description="Missing or invalid access token."),
        },
    )
)
class SessionListView(ListAPIView):
    authentication_classes = [RobustTokenAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = SessionSerializer

    def get_queryset(self):
        return Session.objects.filter(
            user=self.request.user, state=Session.State.ACTIVE
        )

    def get_serializer_context(self):
        ctx = super().get_serializer_context()
        ctx["current_session"] = self.request.auth.session
        return ctx


class RevokeSessionView(APIView):
    authentication_classes = [RobustTokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        # tags=["Sessions"],
        summary="Revoke a session",
        description=(
            "Revoke a specific session by its UUID. "
            "Users can only revoke their **own** sessions.\n\n"
            "Use the session `id` from `GET /auth/sessions/`. "
            "Useful for 'Sign out from this device' on the manage devices screen."
        ),
        parameters=[
            OpenApiParameter(
                name="session_id",
                type=OpenApiTypes.UUID,
                location=OpenApiParameter.PATH,
                description="UUID of the session to revoke.",
                required=True,
            )
        ],
        request=None,
        responses={
            200: OpenApiResponse(
                response=_DetailResponse,
                description="Session revoked.",
                examples=[
                    OpenApiExample("Success", value={"detail": "Session revoked."})
                ],
            ),
            401: OpenApiResponse(description="Missing or invalid access token."),
            404: OpenApiResponse(
                response=_DetailResponse,
                description="Session not found or does not belong to the current user.",
                examples=[
                    OpenApiExample("Not found", value={"detail": "Session not found."})
                ],
            ),
        },
    )
    def delete(self, request, session_id):
        try:
            session = Session.objects.get(
                pk=session_id, user=request.user, state=Session.State.ACTIVE
            )
        except Session.DoesNotExist:
            return Response(
                {"detail": "Session not found."}, status=status.HTTP_404_NOT_FOUND
            )
        SessionManager.logout_session(session)
        return Response({"detail": "Session revoked."}, status=status.HTTP_200_OK)


@extend_schema_view(
    list=extend_schema(
        # tags=["Audit"],
        summary="Login & activity history",
        description=(
            "Returns the **authentication event log** for the authenticated user, "
            "ordered by most recent first.\n\n"
            "Includes login successes, failures, logouts, token refreshes, "
            "reuse detections, and password changes.\n\n"
            "Use `?limit=N` to control how many records are returned (default: 50)."
        ),
        parameters=[
            OpenApiParameter(
                name="limit",
                type=OpenApiTypes.INT,
                location=OpenApiParameter.QUERY,
                description="Maximum number of history entries to return. Defaults to 50.",
                required=False,
                default=50,
            )
        ],
        responses={
            200: OpenApiResponse(
                response=LoginHistorySerializer(many=True),
                description="List of authentication events.",
                examples=[
                    OpenApiExample(
                        "History entries",
                        value=[
                            {
                                "id": 5,
                                "event": "token_refresh",
                                "ip_address": "41.58.12.34",
                                "user_agent": "Mozilla/5.0 (Linux; Android 13 ...)",
                                "extra": {},
                                "timestamp": "2025-06-01T14:05:00Z",
                            },
                            {
                                "id": 4,
                                "event": "login_success",
                                "ip_address": "41.58.12.34",
                                "user_agent": "Mozilla/5.0 (Linux; Android 13 ...)",
                                "extra": {},
                                "timestamp": "2025-06-01T10:23:00Z",
                            },
                            {
                                "id": 3,
                                "event": "login_failure",
                                "ip_address": "185.22.10.1",
                                "user_agent": "python-requests/2.31.0",
                                "extra": {"username": "alice", "failure_count": 3},
                                "timestamp": "2025-06-01T10:20:00Z",
                            },
                        ],
                    )
                ],
            ),
            401: OpenApiResponse(description="Missing or invalid access token."),
        },
    )
)
class LoginHistoryView(ListAPIView):
    authentication_classes = [RobustTokenAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = LoginHistorySerializer

    def get_queryset(self):
        return LoginHistory.objects.filter(user=self.request.user)[
            : self.request.query_params.get("limit", 50)
        ]