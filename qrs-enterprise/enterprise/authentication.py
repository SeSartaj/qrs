"""Authentication backends for QRS Enterprise.

- ``ApiKeyAuthentication`` — DRF authentication via ``Authorization: ApiKey <key>``
  or ``X-Api-Key: <key>``. Resolves the key to its owning user (for audit
  attribution) and attaches the ApiKey instance to the request.
"""
from __future__ import annotations

from django.utils import timezone
from rest_framework import authentication, exceptions

from .models import ApiKey


class ApiKeyAuthentication(authentication.BaseAuthentication):
    """Authenticate a request using a scoped API key."""

    keyword = "ApiKey"

    def authenticate(self, request):
        raw_key = self._extract_key(request)
        if raw_key is None:
            return None

        key_hash = ApiKey.hash_key(raw_key)
        try:
            api_key = ApiKey.objects.select_related("owner").get(key_hash=key_hash)
        except ApiKey.DoesNotExist:
            raise exceptions.AuthenticationFailed("Invalid API key")

        if not api_key.is_active:
            raise exceptions.AuthenticationFailed("API key is inactive")
        if api_key.expires_at and api_key.expires_at <= timezone.now():
            raise exceptions.AuthenticationFailed("API key has expired")

        # Attach the ApiKey for permission checks + audit attribution.
        request.api_key = api_key
        user = api_key.owner
        if user is None or not user.is_active:
            raise exceptions.AuthenticationFailed("API key owner is inactive")
        return (user, api_key)

    def authenticate_header(self, request):
        return self.keyword

    @staticmethod
    def _extract_key(request) -> str | None:
        auth = request.META.get("HTTP_AUTHORIZATION", "")
        if auth.startswith("ApiKey "):
            return auth[len("ApiKey "):].strip()
        return request.META.get("HTTP_X_API_KEY") or None