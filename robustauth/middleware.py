"""
RobustAuth middleware.

RobustAuthMiddleware
    Attaches ``request.robust_session`` for authenticated requests.
    Handles sliding session TTL refresh on every request.
    Checks token expiry inline so expired tokens return 401 without hitting the view.

Usage::

    MIDDLEWARE = [
        ...
        "robustauth.middleware.RobustAuthMiddleware",
    ]
"""
import json

from django.http import HttpRequest, JsonResponse
from django.utils import timezone

from .conf import robust_settings
from .models import AccessToken


class RobustAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request: HttpRequest):
        request.robust_session = None
        self._attach_session(request)
        response = self.get_response(request)
        return response

    # ------------------------------------------------------------------

    def _attach_session(self, request: HttpRequest) -> None:
        raw_token = self._extract_token(request)
        if not raw_token:
            return

        at = AccessToken.authenticate(raw_token)
        if at is None:
            return

        request.robust_session = at.session

    @staticmethod
    def _extract_token(request: HttpRequest) -> str | None:
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        parts = auth_header.split()
        if len(parts) == 2 and parts[0] in ("Bearer", "Token"):
            return parts[1]
        return None