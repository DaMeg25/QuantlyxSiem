from django.urls import path

from . import views

urlpatterns = [
    path("", views.overview, name="overview"),
    path("accounts/", views.accounts, name="accounts"),
    path("accounts/<int:pk>/", views.account_detail, name="account-detail"),
    path("findings/", views.findings, name="findings"),
    path("usage/", views.usage, name="usage"),
    path("access/", views.access, name="access"),
    path("coverage/", views.coverage, name="coverage"),
]
