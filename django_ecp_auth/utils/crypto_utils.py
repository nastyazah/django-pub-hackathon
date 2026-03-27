from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from django_ecp_auth.exceptions import EcpValidationError


@dataclass(frozen=True)
class DerivedKey:
    key: bytes
    salt: bytes


def derive_key_from_password(password: bytes, *, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """Derive an encryption key from a password using PBKDF2-HMAC-SHA256."""
    if not password:
        raise ValueError("Password must not be empty.")
    salt_bytes = salt or os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_bytes,
        iterations=200_000,
    )
    return kdf.derive(password), salt_bytes


def generate_key_pair(*, password: bytes) -> tuple[str, str]:
    """Generate an EC key pair, returning (private_pem, public_pem).

    Private key is encrypted with AES-GCM using the derived password key.
    """
    if len(password) != 32:
        raise ValueError("Derived password key must be 32 bytes.")

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    nonce = os.urandom(12)
    aesgcm = AESGCM(password)
    ciphertext = aesgcm.encrypt(nonce, private_pem, associated_data=None)
    wrapped = base64.b64encode(nonce + ciphertext).decode("ascii")

    encrypted_private_pem = (
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
        + wrapped
        + "\n-----END ENCRYPTED PRIVATE KEY-----\n"
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return encrypted_private_pem, public_pem


def verify_signature(
    *,
    public_key_pem: str,
    data: bytes,
    signature: bytes,
) -> None:
    """Verify a signature over data using the provided public key PEM."""
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))

    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
            return
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return
    except InvalidSignature as exc:
        raise EcpValidationError("Invalid signature.") from exc

    raise EcpValidationError("Unsupported public key type for signature verification.")

