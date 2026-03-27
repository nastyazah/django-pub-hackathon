from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from django.conf import settings

from django_ecp_auth.exceptions import EcpConfigError


@dataclass(frozen=True)
class EcpAuthSettings:
    trusted_ca_certs: str
    cert_validation_enabled: bool
    user_model_field: str
    auto_create_user: bool
    login_template: str
    require_step1_session: bool


def get_ecp_settings() -> EcpAuthSettings:
    raw: dict[str, Any] = getattr(settings, "ECP_AUTH", {})

    def _get(key: str, default: Any) -> Any:
        return raw.get(key, default)

    trusted = str(_get("TRUSTED_CA_CERTS", "") or "")
    if trusted and not Path(trusted).exists():
        raise EcpConfigError(f"ECP_AUTH['TRUSTED_CA_CERTS'] path does not exist: {trusted}")

    return EcpAuthSettings(
        trusted_ca_certs=trusted,
        cert_validation_enabled=bool(_get("CERT_VALIDATION_ENABLED", True)),
        user_model_field=str(_get("USER_MODEL_FIELD", "username")),
        auto_create_user=bool(_get("AUTO_CREATE_USER", False)),
        login_template=str(_get("LOGIN_TEMPLATE", "auth/ecp_login.html")),
        require_step1_session=bool(_get("REQUIRE_STEP1_SESSION", True)),
    )

