from __future__ import annotations

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend
from django.http import HttpRequest

from django_ecp_auth.conf import get_ecp_settings

UserModel = get_user_model()


class EcpAuthBackend(BaseBackend):
    """Authenticate a user using an identifier provided by ECP flow."""

    def authenticate(self, request: HttpRequest, **credentials):
        ecp_user_value = credentials.get("ecp_user_value")
        if not ecp_user_value:
            return None

        cfg = get_ecp_settings()
        lookup = {cfg.user_model_field: ecp_user_value}
        try:
            return UserModel.objects.get(**lookup)
        except UserModel.DoesNotExist:
            if not cfg.auto_create_user:
                return None
            return UserModel.objects.create_user(
                username=ecp_user_value,
                email=ecp_user_value if "@" in str(ecp_user_value) else "",
            )

    def get_user(self, user_id: int):
        try:
            return UserModel.objects.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None

