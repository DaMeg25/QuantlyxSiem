from django.urls import path

from . import views

urlpatterns = [
    path("queue/", views.approval_queue, name="access-queue"),
    path("request/", views.request_create, name="access-request-create"),
    path("requests/<str:reference>/", views.request_detail, name="access-request-detail"),
    path("requests/<str:reference>/decide/", views.request_decide, name="access-request-decide"),
    path("requests/<str:reference>/handoff/", views.request_handoff, name="access-request-handoff"),
    path("requests/<str:reference>/revoke/", views.request_revoke, name="access-request-revoke"),
]
