from django.contrib import admin
from django.utils.html import format_html

from .models import AccessToken, LoginHistory, RefreshToken, Session


@admin.register(Session)
class SessionAdmin(admin.ModelAdmin):
    list_display = [
        "id",
        "user",
        "state",
        "ip_address",
        "device_type",
        "os_family",
        "browser_family",
        "created_at",
        "last_activity",
    ]
    list_filter = ["state", "device_type", "os_family"]
    search_fields = ["user__username", "ip_address", "device_name"]
    readonly_fields = [
        "id", "user", "ip_address", "user_agent", "device_type",
        "os_family", "browser_family", "device_name", "created_at",
        "last_activity", "revoked_at",
    ]
    actions = ["revoke_sessions"]

    @admin.action(description="Revoke selected sessions")
    def revoke_sessions(self, request, queryset):
        from .session_manager import SessionManager
        count = 0
        for session in queryset.filter(state=Session.State.ACTIVE):
            SessionManager.logout_session(session)
            count += 1
        self.message_user(request, f"Revoked {count} session(s).")


@admin.register(AccessToken)
class AccessTokenAdmin(admin.ModelAdmin):
    list_display = ["session", "expires_at", "created_at", "status_badge"]
    readonly_fields = ["session", "token_hash", "expires_at", "created_at"]
    search_fields = ["session__user__username"]

    @admin.display(description="Status")
    def status_badge(self, obj):
        if obj.is_expired():
            return format_html('<span style="color:red;">Expired</span>')
        return format_html('<span style="color:green;">Active</span>')


@admin.register(RefreshToken)
class RefreshTokenAdmin(admin.ModelAdmin):
    list_display = [
        "session", "family_id", "is_used", "is_revoked", "expires_at", "created_at"
    ]
    list_filter = ["is_used", "is_revoked"]
    readonly_fields = [
        "session", "token_hash", "parent", "family_id",
        "is_used", "is_revoked", "expires_at", "created_at",
    ]
    search_fields = ["session__user__username"]


@admin.register(LoginHistory)
class LoginHistoryAdmin(admin.ModelAdmin):
    list_display = ["user", "event", "ip_address", "timestamp"]
    list_filter = ["event"]
    search_fields = ["user__username", "ip_address"]
    readonly_fields = [
        "user", "session", "event", "ip_address", "user_agent", "extra", "timestamp"
    ]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False