from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from django_ecp_auth.exceptions import EcpValidationError


def load_certificate(cert_bytes: bytes) -> x509.Certificate:
    """Load an X.509 certificate from PEM or DER bytes."""
    try:
        return x509.load_pem_x509_certificate(cert_bytes)
    except ValueError:
        try:
            return x509.load_der_x509_certificate(cert_bytes)
        except ValueError as exc:
            raise EcpValidationError("Unable to parse certificate (not valid PEM/DER).") from exc


def basic_certificate_checks(cert: x509.Certificate) -> None:
    """Basic certificate validity checks (time window)."""
    now = datetime.now(UTC)
    if cert.not_valid_before_utc > now:
        raise EcpValidationError("Certificate is not yet valid.")
    if cert.not_valid_after_utc < now:
        raise EcpValidationError("Certificate has expired.")


def certificate_public_key_pem(cert: x509.Certificate) -> str:
    return cert.public_key().public_bytes(Encoding.PEM).decode("utf-8")


def validate_certificate_chain_if_enabled(*, cert_der_or_pem: bytes, ca_bundle_path: str) -> None:
    """Optional chain validation using certvalidator (if installed/configured)."""
    if not ca_bundle_path:
        return
    ca_path = Path(ca_bundle_path)
    if not ca_path.exists():
        raise EcpValidationError(f"Trusted CA bundle not found: {ca_bundle_path}")

    try:
        from asn1crypto import pem
        from asn1crypto.x509 import Certificate
        from certvalidator import CertificateValidator, ValidationContext
    except Exception as exc:  # pragma: no cover
        raise EcpValidationError("certvalidator/asn1crypto is required for chain validation.") from exc

    cert_bytes = cert_der_or_pem
    if pem.detect(cert_bytes):
        _, _, cert_bytes = pem.unarmor(cert_bytes)

    user_cert = Certificate.load(cert_bytes)

    ca_bytes = ca_path.read_bytes()
    ca_certs: list[Certificate] = []
    if pem.detect(ca_bytes):
        for _, _, der in pem.unarmor(ca_bytes, multiple=True):
            ca_certs.append(Certificate.load(der))
    else:
        ca_certs.append(Certificate.load(ca_bytes))

    context = ValidationContext(trust_roots=ca_certs)
    CertificateValidator(user_cert, validation_context=context).validate_usage(set())

