"""DRF permission classes for QRS Enterprise.

Authorization model:
- Admins (``role == 'admin'`` or ``is_staff``) can do everything.
- Signing a TCert requires a ``TcertGrant`` for that TCert.
- CA operations (revoke / block / unblock) require the corresponding Django
  model permission (``enterprise.can_revoke_tcert`` etc.) OR an API key with
  that permission.
"""
from __future__ import annotations

from rest_framework import permissions

from .models import TcertGrant


def _is_admin(user) -> bool:
    return bool(user and (user.is_staff or getattr(user, "role", "") == "admin"))


class IsAdmin(permissions.BasePermission):
    """Allow only admins."""

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated) and _is_admin(request.user)


class CanSignTcert(permissions.BasePermission):
    """Allow signing with a TCert if the user has a grant for it (or is admin)."""

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)

    def has_object_permission(self, request, view, obj):
        if _is_admin(request.user):
            return True
        return TcertGrant.objects.filter(user=request.user, tcert=obj).exists()


class CanRevokeTcert(permissions.BasePermission):
    """Allow revoking a TCert via Django permission or API-key scope.

    When the request is authenticated with an API key, the key's scoped
    permissions are authoritative (the owner's admin status does not bypass
    the key's scope).
    """

    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        api_key = getattr(request, "api_key", None)
        if api_key is not None:
            return api_key.has_perm("enterprise.can_revoke_tcert")
        if _is_admin(request.user):
            return True
        return request.user.has_perm("enterprise.can_revoke_tcert")


class CanBlockSdoc(permissions.BasePermission):
    """Allow blocking an SDoc via Django permission or API-key scope."""

    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        api_key = getattr(request, "api_key", None)
        if api_key is not None:
            return api_key.has_perm("enterprise.can_block_sdoc")
        if _is_admin(request.user):
            return True
        return request.user.has_perm("enterprise.can_block_sdoc")


class CanUnblockSdoc(permissions.BasePermission):
    """Allow unblocking an SDoc via Django permission or API-key scope."""

    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        api_key = getattr(request, "api_key", None)
        if api_key is not None:
            return api_key.has_perm("enterprise.can_unblock_sdoc")
        if _is_admin(request.user):
            return True
        return request.user.has_perm("enterprise.can_unblock_sdoc")