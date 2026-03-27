from __future__ import annotations


class EcpAuthError(Exception):
    """Base error for ECP auth flow."""


class EcpConfigError(EcpAuthError):
    """Raised when settings/configuration is invalid."""


class EcpValidationError(EcpAuthError):
    """Raised when a certificate/signature fails validation."""

