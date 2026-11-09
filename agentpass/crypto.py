"""Key handling: the gateway's signing key and agent key pairs (Ed25519)."""

from __future__ import annotations

import base64
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def generate_keypair() -> tuple[str, str]:
    """Return (private_key_pem, public_key_pem) for a new Ed25519 key."""
    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


def load_private_key(pem: str) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("expected an Ed25519 private key")
    return key


def load_public_key(pem: str) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem.encode())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("expected an Ed25519 public key")
    return key


def load_or_create_issuer_key(path: Path) -> Ed25519PrivateKey:
    """The gateway's own signing key, created on first start."""
    if path.exists():
        return load_private_key(path.read_text())
    path.parent.mkdir(parents=True, exist_ok=True)
    private_pem, _ = generate_keypair()
    path.write_text(private_pem)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return load_private_key(private_pem)


def public_jwk(key: Ed25519PrivateKey, kid: str) -> dict:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return {"kty": "OKP", "crv": "Ed25519", "x": x, "kid": kid, "alg": "EdDSA", "use": "sig"}
