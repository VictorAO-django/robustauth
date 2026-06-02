"""
Serializers for the RobustAuth API endpoints.
"""
from django.contrib.auth import authenticate, get_user_model
from rest_framework import serializers

from .models import LoginHistory, Session
from .session_manager import SessionManager

User = get_user_model()


# ---------------------------------------------------------------------------
# Base login serializer — subclass this to customise the login fields
# ---------------------------------------------------------------------------

class BaseLoginSerializer(serializers.Serializer):
    """
    Base class for all RobustAuth login serializers.

    Subclass this to customise the login credential fields.
    The only contract is that your subclass must set ``attrs["user"]``
    inside ``validate()`` before returning.

    Example — email + password login::

        class EmailLoginSerializer(BaseLoginSerializer):
            email    = serializers.EmailField(write_only=True)
            password = serializers.CharField(write_only=True, style={"input_type": "password"})

            def validate(self, attrs):
                try:
                    user = User.objects.get(email=attrs["email"])
                except User.DoesNotExist:
                    raise serializers.ValidationError("Invalid credentials.")
                if not user.check_password(attrs["password"]):
                    raise serializers.ValidationError("Invalid credentials.")
                if not user.is_active:
                    raise serializers.ValidationError("User account is disabled.")
                attrs["user"] = user
                return attrs

    Then point RobustAuth at it::

        ROBUST_AUTH = {
            "LOGIN_SERIALIZER": "myapp.serializers.EmailLoginSerializer",
        }
    """

    def validate(self, attrs):
        raise NotImplementedError(
            "Subclasses of BaseLoginSerializer must implement validate()."
        )

    def save(self, **kwargs):
        request = self.context.get("request")
        user = self.validated_data["user"]
        ip = _get_client_ip(request)
        ua = request.META.get("HTTP_USER_AGENT", "") if request else ""
        pair = SessionManager.create_session(user, ip_address=ip, user_agent=ua)
        self.validated_data["pair"] = pair
        return pair

    def to_representation(self, instance):
        pair = self.validated_data.get("pair")
        if pair is None:
            return {}
        return {
            "access_token": pair.access_token,
            "refresh_token": pair.refresh_token,
            "session_id": str(pair.session.id),
            "token_type": "Bearer",
        }


# ---------------------------------------------------------------------------
# Built-in login serializer variants
# ---------------------------------------------------------------------------

class UsernameLoginSerializer(BaseLoginSerializer):
    """
    Default login serializer — authenticates with ``username`` + ``password``.
    Works out of the box with Django's default User model.
    """
    username = serializers.CharField(
        write_only=True,
        help_text="Your account username.",
    )
    password = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
        help_text="Your account password.",
    )

    def validate(self, attrs):
        request = self.context.get("request")
        user = authenticate(
            request=request,
            username=attrs["username"],
            password=attrs["password"],
        )
        if not user:
            raise serializers.ValidationError("Invalid credentials.", code="authorization")
        if not user.is_active:
            raise serializers.ValidationError("User account is disabled.", code="authorization")
        attrs["user"] = user
        return attrs


class EmailLoginSerializer(BaseLoginSerializer):
    """
    Login with ``email`` + ``password``.
    Use this when your User model or AUTH_USER_MODEL uses email as the identifier.

        ROBUST_AUTH = {
            "LOGIN_SERIALIZER": "robustauth.serializers.EmailLoginSerializer",
        }
    """
    email = serializers.EmailField(
        write_only=True,
        help_text="The email address associated with your account.",
    )
    password = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
        help_text="Your account password.",
    )

    def validate(self, attrs):
        email = attrs["email"].lower().strip()
        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist as err:
            raise serializers.ValidationError(
                "Invalid credentials.", code="authorization"
            ) from err
        if not user.check_password(attrs["password"]):
            raise serializers.ValidationError("Invalid credentials.", code="authorization")
        if not user.is_active:
            raise serializers.ValidationError("User account is disabled.", code="authorization")
        attrs["user"] = user
        return attrs


class EmailOrUsernameLoginSerializer(BaseLoginSerializer):
    """
    Flexible login — accepts either ``username`` or ``email`` in the same field,
    plus ``password``. Tries username first, falls back to email lookup.

        ROBUST_AUTH = {
            "LOGIN_SERIALIZER": "robustauth.serializers.EmailOrUsernameLoginSerializer",
        }
    """
    login = serializers.CharField(
        write_only=True,
        help_text="Your username or email address.",
    )
    password = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
        help_text="Your account password.",
    )

    def validate(self, attrs):
        request = self.context.get("request")
        login = attrs["login"].strip()
        password = attrs["password"]

        # Try username auth first (Django backend handles the password check)
        user = authenticate(request=request, username=login, password=password)

        # Fall back to email lookup
        if user is None:
            try:
                matched = User.objects.get(email__iexact=login)
                if matched.check_password(password):
                    user = matched
            except User.DoesNotExist:
                pass

        if not user:
            raise serializers.ValidationError("Invalid credentials.", code="authorization")
        if not user.is_active:
            raise serializers.ValidationError("User account is disabled.", code="authorization")
        attrs["user"] = user
        return attrs


# Alias — default serializer used when LOGIN_SERIALIZER is not set
LoginSerializer = UsernameLoginSerializer


class RefreshTokenSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(write_only=True)

    access_token = serializers.CharField(read_only=True)
    refresh_token_new = serializers.CharField(read_only=True)

    def validate_refresh_token(self, value):
        self._raw_refresh = value
        return value

    def save(self, **kwargs):
        request = self.context.get("request")
        ip = _get_client_ip(request)
        ua = request.META.get("HTTP_USER_AGENT", "") if request else ""

        try:
            pair = SessionManager.refresh_session(
                self._raw_refresh, ip_address=ip, user_agent=ua
            )
        except ValueError as exc:
            raise serializers.ValidationError(str(exc)) from exc

        self._pair = pair
        return pair

    def to_representation(self, instance):
        return {
            "access_token": self._pair.access_token,
            "refresh_token": self._pair.refresh_token,
            "token_type": "Bearer",
        }


class LogoutSerializer(serializers.Serializer):
    """No input needed — session is taken from the authenticated request."""
    pass


class LogoutAllSerializer(serializers.Serializer):
    """Logout every *other* session; current session optionally kept alive."""
    keep_current = serializers.BooleanField(default=True)


# ---------------------------------------------------------------------------
# Session detail serializers
# ---------------------------------------------------------------------------

class SessionSerializer(serializers.ModelSerializer):
    is_current = serializers.SerializerMethodField()

    class Meta:
        model = Session
        fields = [
            "id",
            "state",
            "ip_address",
            "device_type",
            "os_family",
            "browser_family",
            "device_name",
            "created_at",
            "last_activity",
            "is_current",
        ]
        read_only_fields = fields

    def get_is_current(self, obj) -> bool:
        current = self.context.get("current_session")
        return current is not None and obj.pk == current.pk


class LoginHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = LoginHistory
        fields = [
            "id",
            "event",
            "ip_address",
            "user_agent",
            "extra",
            "timestamp",
        ]
        read_only_fields = fields


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _get_client_ip(request) -> str | None:
    if request is None:
        return None
    x_forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded:
        return x_forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")