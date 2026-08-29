from django.urls import path

from . import views

urlpatterns = [
    path("tcerts/", views.TcertList.as_view(), name="tcerts"),
    path("tcerts/import/", views.ImportTcertView.as_view(), name="tcert-import"),
    path("tcerts/<str:key_id>/challenge/", views.ChallengeView.as_view(), name="challenge"),
    path("tcerts/<str:key_id>/token/", views.TokenView.as_view(), name="token"),
    path("tcerts/<str:key_id>/objects/", views.ObjectsView.as_view(), name="objects"),
    path("tcerts/<str:key_id>/statements/", views.TcertStatementUpload.as_view(), name="tcert-statement-upload"),
    path("tcerts/<str:key_id>/self-revocation/", views.SelfRevocationUpload.as_view(), name="self-revocation-upload"),
    path("cas/<str:ca_tcert_id>/attestations/", views.CaAttestationUpload.as_view(), name="ca-attestation-upload"),
    path("cas/<str:ca_tcert_id>/statements/", views.CaStatementUpload.as_view(), name="ca-statement-upload"),
    path("cas/<str:ca_tcert_id>/sync/", views.CaSyncView.as_view(), name="ca-sync"),
    path("attachments/<str:attachment_id>/", views.AttachmentDetail.as_view(), name="attachment-detail"),
    path("attachments/", views.AttachmentUpload.as_view(), name="attachment-upload"),
    path("sync/", views.SyncView.as_view(), name="sync"),
]
