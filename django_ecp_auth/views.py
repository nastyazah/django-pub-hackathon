from __future__ import annotations

import logging

from django.contrib import messages
from django.contrib.auth import authenticate, get_user_model, login
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.views import View

from django_ecp_auth.conf import get_ecp_settings
from django_ecp_auth.exceptions import EcpValidationError

logger = logging.getLogger(__name__)
User = get_user_model()


class EcpLoginView(View):
    """Step 2 of login: verify signature using uploaded certificate."""

    def get(self, request: HttpRequest) -> HttpResponse:
        cfg = get_ecp_settings()
        if cfg.require_step1_session and not request.session.get("partial_auth_user_id"):
            messages.error(request, "Please complete step 1 (email/password) first.")
            return redirect("login")
        return render(request, cfg.login_template)

    def post(self, request: HttpRequest) -> HttpResponse:
        cfg = get_ecp_settings()
        if cfg.require_step1_session and not request.session.get("partial_auth_user_id"):
            messages.error(request, "Please complete step 1 (email/password) first.")
            return redirect("login")

        signature_file = request.FILES.get("signature")
        cert_file = request.FILES.get("certificate")
        signed_data_file = request.FILES.get("signed_data")

        if not (signature_file and cert_file and signed_data_file):
            messages.error(request, "All files are required: signature, certificate, signed data.")
            return redirect("ecp-login")

        try:
            from django_ecp_auth.utils.cert_utils import (
                basic_certificate_checks,
                certificate_public_key_pem,
                load_certificate,
                validate_certificate_chain_if_enabled,
            )
            from django_ecp_auth.utils.crypto_utils import verify_signature

            signature = signature_file.read()
            cert_bytes = cert_file.read()
            signed_data = signed_data_file.read()

            cert = load_certificate(cert_bytes)
            basic_certificate_checks(cert)
            if cfg.cert_validation_enabled and cfg.trusted_ca_certs:
                validate_certificate_chain_if_enabled(cert_der_or_pem=cert_bytes, ca_bundle_path=cfg.trusted_ca_certs)

            public_key_pem = certificate_public_key_pem(cert)
            verify_signature(public_key_pem=public_key_pem, data=signed_data, signature=signature)

            user_id = request.session.get("partial_auth_user_id")
            user = User.objects.filter(pk=user_id).first()
            if not user:
                raise EcpValidationError("User session is invalid. Please login again.")

            if getattr(user, "public_key", None):
                if user.public_key.strip() != public_key_pem.strip():
                    raise EcpValidationError("Certificate does not match user's public key.")

            auth_user = authenticate(request, ecp_user_value=getattr(user, cfg.user_model_field))
            if auth_user is None:
                raise EcpValidationError("ECP backend could not authenticate the user.")

            login(request, auth_user, backend="django_ecp_auth.backends.ecp_backend.EcpAuthBackend")
            request.session.pop("partial_auth_user_id", None)
            logger.info("ECP login success for user_id=%s", auth_user.pk)
            return redirect("dashboard")

        except EcpValidationError as exc:
            logger.warning("ECP validation failed: %s", exc)
            messages.error(request, str(exc))
            return redirect("ecp-login")
        except Exception:
            logger.exception("Unexpected ECP login error")
            messages.error(request, "Unexpected error during ECP verification.")
            return redirect("ecp-login")

