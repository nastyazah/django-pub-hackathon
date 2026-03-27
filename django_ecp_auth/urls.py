from __future__ import annotations

from django.urls import path

from django_ecp_auth.views import EcpLoginView

urlpatterns = [
    path("login/", EcpLoginView.as_view(), name="ecp-login"),
]

