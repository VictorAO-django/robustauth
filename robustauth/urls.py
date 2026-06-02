"""
RobustAuth URL patterns.

Include in your project::

    path("auth/", include("robustauth.urls")),
"""
from django.urls import path

from . import views

app_name = "robustauth"

urlpatterns = [
    path("login/", views.LoginView.as_view(), name="login"),
    path("token/refresh/", views.RefreshView.as_view(), name="token-refresh"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
    path("logout/all/", views.LogoutAllView.as_view(), name="logout-all"),
    path("sessions/", views.SessionListView.as_view(), name="session-list"),
    path(
        "sessions/<uuid:session_id>/",
        views.RevokeSessionView.as_view(),
        name="session-revoke",
    ),
    path("history/", views.LoginHistoryView.as_view(), name="login-history"),
]