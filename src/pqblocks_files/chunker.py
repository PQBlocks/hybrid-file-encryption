"""Chunker for the pfsh v1 body.

Contract:
  _chunk(plaintext: bytes, file_key: bytes (16B)) -> list[(nonce: bytes (12B), chunk: bytes)]
  _unchunk(chunked: list[(nonce: bytes (12B), chunk: bytes)], file_key: bytes) -> bytes   (private: test helper)

Where chunk = ciphertext || tag (16B Poly1305 tag)
- Chunks are 64 KiB max ciphertext
- Nonce structure (12 bytes):
  - Bytes 0-7: big-endian 64-bit chunk counter (starting at 0)
  - Byte 8: 0x00 (non-final) or 0x01 (final chunk)
  - Bytes 9-11: reserved, MUST be 0x00
"""

from __future__ import annotations

import os
from typing import List, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pqblocks_files.pqtypes import TagVerificationFailed

CHUNK_SIZE = 65536  # 64 KiB


def _derive_payload_key(file_key: bytes, chunk_nonce: bytes) -> bytes:
    """HKDF-SHA256(file_key, salt=chunk_nonce, info="payload") -> 32B."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=chunk_nonce,
        info=b"payload",
    )
    return hkdf.derive(file_key)


def _make_nonce(counter: int, is_final: bool) -> bytes:
    """Construct 12-byte nonce from counter and final flag."""
    flag = 0x01 if is_final else 0x00
    return counter.to_bytes(8, "big") + bytes([flag]) + b"\x00\x00\x00"


def _chunk(plaintext: bytes, file_key: bytes) -> List[Tuple[bytes, bytes]]:
    """Encrypt plaintext into chunks.

    Args:
        plaintext: Data to encrypt
        file_key: 16-byte key for HKDF derivation

    Returns:
        List of (nonce: 12B, ciphertext||tag: 16B tag) tuples

    Contract:
      - Number of chunks = ceil(len(plaintext) / 65536)
      - Each chunk max 65536 bytes ciphertext
      - For empty file: 1 chunk with 0-byte ciphertext + 16-byte tag
      - Nonce counter starts at 0, increments per chunk
      - Final chunk has flag=0x01
    """
    if not isinstance(plaintext, bytes):
        raise TypeError(f"plaintext must be bytes, got {type(plaintext).__name__}")
    if len(file_key) != 16:
        raise ValueError(f"file_key must be 16 bytes, got {len(file_key)}")

    # Handle empty plaintext: 1 chunk with 0-byte ciphertext
    if not plaintext:
        nonce = _make_nonce(0, True)
        key = _derive_payload_key(file_key, nonce)
        aead = ChaCha20Poly1305(key)
        ct_and_tag = aead.encrypt(nonce, b"", b"")
        return [(nonce, ct_and_tag)]

    # Split into chunks
    num_chunks = (len(plaintext) + CHUNK_SIZE - 1) // CHUNK_SIZE

    result: List[Tuple[bytes, bytes]] = []
    for i in range(num_chunks):
        is_final = (i == num_chunks - 1)
        nonce = _make_nonce(i, is_final)
        chunk_pt = plaintext[i * CHUNK_SIZE : (i + 1) * CHUNK_SIZE]

        key = _derive_payload_key(file_key, nonce)
        aead = ChaCha20Poly1305(key)
        ct_and_tag = aead.encrypt(nonce, chunk_pt, b"")

        result.append((nonce, ct_and_tag))

    return result


def _unchunk(
    chunked: List[Tuple[bytes, bytes]], file_key: bytes
) -> bytes:
    """Private test helper: decrypt chunks back to plaintext.

    Trusts the nonces it is given (no order, final-flag or empty-input checks); the public
    decrypt() enforces those. Not part of the API.

    Args:
        chunked: List of (nonce: 12B, ciphertext||tag) tuples
        file_key: 16-byte key for HKDF derivation

    Returns:
        Original plaintext

    Raises:
        TagVerificationFailed: If any chunk's Poly1305 tag doesn't verify
    """
    if not chunked:
        return b""

    plaintext = b""
    for nonce, ct_and_tag in chunked:
        key = _derive_payload_key(file_key, nonce)
        aead = ChaCha20Poly1305(key)
        try:
            pt = aead.decrypt(nonce, ct_and_tag, b"")
        except Exception as e:
            raise TagVerificationFailed(f"chunk decryption failed: {e}") from e
        plaintext += pt

    return plaintext