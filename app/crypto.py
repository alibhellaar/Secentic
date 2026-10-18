"""Ed25519 helpers for agent identity (M2). Pure functions, no web or database code.

The canonical request format must stay identical to secentic_sdk/__init__.py.
"""
import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SIGNATURE_VERSION = "SECENTIC-V1"

# Encodings (sign bit cleared, non-canonical forms included) of the 8 small-order points of
# edwards25519, the same blocklist libsodium uses. Signatures for such a key can be forged
# without any private key (e.g. key 01 00..00 accepts R = 01 00..00, S = 0 for every message).
_SMALL_ORDER_KEYS = frozenset(bytes.fromhex(h) for h in (
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
))


def load_public_key(public_key_b64: str) -> tuple[Ed25519PublicKey, str]:
    """Decode a base64 raw Ed25519 public key. Returns the key and its key ID (SHA-256 thumbprint).

    Raises ValueError if the input is not a usable key.
    """
    raw = base64.b64decode(public_key_b64, validate=True)  # binascii.Error is a ValueError
    if len(raw) == 32 and raw[:31] + bytes([raw[31] & 0x7F]) in _SMALL_ORDER_KEYS:
        raise ValueError("small-order key, signatures for it can be forged")
    return Ed25519PublicKey.from_public_bytes(raw), hashlib.sha256(raw).hexdigest()


def canonical_request(method: str, path: str, query: str, key_id: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    """The exact bytes an agent signs. Covers everything an attacker could alter or replay."""
    return "\n".join([
        SIGNATURE_VERSION,
        method.upper(),
        path,
        query,
        key_id,
        timestamp,
        nonce,
        hashlib.sha256(body).hexdigest(),
    ]).encode()


def verify_signature(public_key_b64: str, signature_b64: str, message: bytes) -> bool:
    try:
        public_key, _ = load_public_key(public_key_b64)
        public_key.verify(base64.b64decode(signature_b64, validate=True), message)
    except (InvalidSignature, ValueError):
        return False
    return True
