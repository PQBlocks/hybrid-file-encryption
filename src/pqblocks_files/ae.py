"""AEAD layer: ChaCha20-Poly1305 and the HKDF key derivations for the pfsh v1 body and header.

Contract:
  derive_payload_key(file_key: bytes, chunk_nonce: bytes) -> 32B
  derive_header_mac_key(file_key: bytes) -> 32B
  chacha20poly1305_encrypt(key, nonce, pt, aad=b'') -> ciphertext || tag
  chacha20poly1305_decrypt(key, nonce, ct_tag, aad=b'') -> plaintext

Primitives come from pyca/cryptography (audited library).
HKDF-SHA256 via the same library. No hand-rolled crypto.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pqblocks_files.pqtypes import TagVerificationFailed


def derive_payload_key(file_key: bytes, chunk_nonce: bytes) -> bytes:
    """HKDF-SHA256(ikm=file_key, salt=chunk_nonce, info='payload') -> 32B."""
    if len(file_key) != 16:
        raise ValueError(f"file_key must be 16 bytes, got {len(file_key)}")
    if len(chunk_nonce) != 12:
        raise ValueError(f"chunk_nonce must be 12 bytes, got {len(chunk_nonce)}")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=chunk_nonce,
        info=b"payload",
    )
    return hkdf.derive(file_key)


def derive_header_mac_key(file_key: bytes) -> bytes:
    """HKDF-SHA256(ikm=file_key, salt=b'', info='header') -> 32B."""
    if len(file_key) != 16:
        raise ValueError(f"file_key must be 16 bytes, got {len(file_key)}")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",
        info=b"header",
    )
    return hkdf.derive(file_key)


def chacha20poly1305_encrypt(
    key: bytes,
    nonce: bytes,
    pt: bytes,
    aad: bytes = b"",
) -> bytes:
    """Encrypt pt with ChaCha20-Poly1305. Returns ciphertext || tag.

    key: 32 bytes, nonce: 12 bytes. Output length = len(pt) + 16.
    """
    if len(key) != 32:
        raise ValueError(f"key must be 32 bytes, got {len(key)}")
    if len(nonce) != 12:
        raise ValueError(f"nonce must be 12 bytes, got {len(nonce)}")
    aead = ChaCha20Poly1305(key)
    return aead.encrypt(nonce, pt, aad)


def chacha20poly1305_decrypt(
    key: bytes,
    nonce: bytes,
    ct_tag: bytes,
    aad: bytes = b"",
) -> bytes:
    """Decrypt ct_tag with ChaCha20-Poly1305. Returns plaintext.

    Raises TagVerificationFailed if the Poly1305 tag does not verify.
    key: 32 bytes, nonce: 12 bytes.
    """
    if len(key) != 32:
        raise ValueError(f"key must be 32 bytes, got {len(key)}")
    if len(nonce) != 12:
        raise ValueError(f"nonce must be 12 bytes, got {len(nonce)}")
    if len(ct_tag) < 16:
        raise TagVerificationFailed(
            f"ct_tag too short: {len(ct_tag)} bytes (minimum 16 for tag)"
        )
    aead = ChaCha20Poly1305(key)
    try:
        return aead.decrypt(nonce, ct_tag, aad)
    except InvalidTag:
        raise TagVerificationFailed("Poly1305 tag verification failed") from None
