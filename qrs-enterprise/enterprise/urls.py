"""URL configuration for the enterprise app."""
from django.urls import path

from . import views

urlpatterns = [
    # Auth
    path("auth/login/", views.login_view, name="login"),
    path("auth/logout/", views.logout_view, name="logout"),
    path("auth/me/", views.me_view, name="me"),
    # TCerts
    path("tcerts/", views.TcertListCreateView.as_view(), name="tcert-list"),
    path("tcerts/<int:pk>/", views.TcertDetailView.as_view(), name="tcert-detail"),
    path("tcerts/<int:pk>/grants/", views.TcertGrantView.as_view(), name="tcert-grants"),
    path("tcerts/<int:pk>/grants/<int:grant_id>/", views.TcertGrantView.as_view(), name="tcert-grant-delete"),
    path("tcerts/<int:pk>/sign/", views.TcertSignView.as_view(), name="tcert-sign"),
    path("tcerts/<int:pk>/attest/", views.TcertAttestView.as_view(), name="tcert-attest"),
    # External-system signing (API key): submit values → signed SDoc + QR PNG.
    path("sign/", views.ExternalSignView.as_view(), name="external-sign"),
    path("tcerts/<int:pk>/revoke/", views.TcertRevokeView.as_view(), name="tcert-revoke"),
    # SDocs (static paths must precede the <str:sdoc_id> capture)
    path("sdocs/", views.SdocListView.as_view(), name="sdoc-list"),
    path("sdocs/verify/", views.SdocVerifyView.as_view(), name="sdoc-verify"),
    path("sdocs/block/", views.SdocBlockView.as_view(), name="sdoc-block"),
    path("sdocs/unblock/", views.SdocUnblockView.as_view(), name="sdoc-unblock"),
    path("sdocs/<str:sdoc_id>/", views.SdocDetailView.as_view(), name="sdoc-detail"),
    # Audit + API keys
    path("logs/", views.AuditLogListView.as_view(), name="audit-log"),
    path("api-keys/", views.ApiKeyListView.as_view(), name="api-key-list"),
    path("api-keys/<int:pk>/", views.ApiKeyDetailView.as_view(), name="api-key-detail"),
]