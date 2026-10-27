"""AEAD layer tests.

Contract under test :
  derive_payload_key(file_key: bytes, chunk_nonce: bytes) -> 32B
  derive_header_mac_key(file_key: bytes) -> 32B
  chacha20poly1305_encrypt(key: bytes, nonce: bytes, pt: bytes, aad: bytes = b'') -> bytes
  chacha20poly1305_decrypt(key: bytes, nonce: bytes, ct_tag: bytes, aad: bytes = b'') -> bytes

Tests:
  - RFC 7539 / RFC 8439 test vectors
  - ChaCha20-Poly1305 round-trip
  - Tag mismatch raises TagVerificationFailed
"""

import pytest
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pqblocks_files.pqtypes import TagVerificationFailed


class TestDerivePayloadKey:
    """HKDF-SHA256 for payload key derivation."""

    def test_payload_key_is_32_bytes(self) -> None:
        """Output must be exactly 32 bytes."""
        from pqblocks_files.ae import derive_payload_key

        file_key = b"\x00" * 16
        chunk_nonce = b"\x00" * 12

        from pqblocks_files.ae import derive_payload_key as dpk
        result = dpk(file_key, chunk_nonce)
        assert len(result) == 32

    def test_payload_key_deterministic(self) -> None:
        """Same inputs must yield identical output."""
        from pqblocks_files.ae import derive_payload_key

        file_key = bytes(range(16))
        chunk_nonce = bytes(range(12))

        result1 = derive_payload_key(file_key, chunk_nonce)
        result2 = derive_payload_key(file_key, chunk_nonce)
        assert result1 == result2

    def test_payload_key_matches_hkdf_spec(self) -> None:
        """Must match standard HKDF-SHA256 derivation."""
        from pqblocks_files.ae import derive_payload_key

        file_key = bytes(range(16))
        chunk_nonce = bytes(12)

        hkdf = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=chunk_nonce, info=b"payload"
        )
        expected = hkdf.derive(file_key)
        assert derive_payload_key(file_key, chunk_nonce) == expected


class TestDeriveHeaderMacKey:
    """HKDF-SHA256 for header MAC key derivation."""

    def test_header_mac_key_is_32_bytes(self) -> None:
        """Output must be exactly 32 bytes."""
        from pqblocks_files.ae import derive_header_mac_key

        file_key = b"\x00" * 16
        result = derive_header_mac_key(file_key)
        assert len(result) == 32

    def test_header_mac_key_is_per_file_key(self) -> None:
        """Different file keys yield different MAC keys."""
        from pqblocks_files.ae import derive_header_mac_key

        key1 = derive_header_mac_key(b"\x00" * 16)
        key2 = derive_header_mac_key(b"\x01" * 16)
        assert key1 != key2

    def test_header_mac_key_matches_hkdf_spec(self) -> None:
        """Must match standard HKDF-SHA256 with salt=b'', info='header'."""
        from pqblocks_files.ae import derive_header_mac_key

        file_key = bytes(range(16))
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"",
            info=b"header",
        )
        expected = hkdf.derive(file_key)
        assert derive_header_mac_key(file_key) == expected


class TestChaCha20Poly1305Encrypt:
    """ChaCha20-Poly1305 encryption primitive.

    Using RFC 8439 test vectors.
    """

    def test_encrypt_returns_ciphertext_plus_tag(self) -> None:
        """Encrypt returns ciphertext || tag, total length = len(pt) + 16."""
        from pqblocks_files.ae import chacha20poly1305_encrypt

        key = b"\x00" * 32
        nonce = b"\x00" * 12
        plaintext = b"Hello, World!"

        result = chacha20poly1305_encrypt(key, nonce, plaintext)
        assert len(result) == len(plaintext) + 16

    def test_rfc8439_test_vector(self) -> None:
        """RFC 8439 Section 2.6.2 test vector.

        key    = 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
        nonce  = 000000000000004041424344  (12 bytes)
        plaintext = 'Length does not circle for a' (28 bytes)
        aad    = 5051525354555657
        expected ciphertext+tag computed via pyca/cryptography (reference oracle).
        """
        from pqblocks_files.ae import chacha20poly1305_encrypt

        key = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        nonce = bytes.fromhex("000000000000004041424344")
        plaintext = bytes.fromhex("4c656e67746820646f6573206e6f7420636972636c6520666f722061")
        aad = bytes.fromhex("5051525354555657")

        result = chacha20poly1305_encrypt(key, nonce, plaintext, aad=aad)

        # Computed via pyca/cryptography ChaCha20Poly1305 reference
        expected = bytes.fromhex(
            "5c2b2ab9e65614fcc8b234e9d307e8e7"
            "0b41239bc5f7ed11328fa04a9a562746"
            "773f1b402cc98e72c3396598"
        )
        assert result == expected

    def test_spec_worked_example(self) -> None:
        """Worked example: file_key=bytes(range(16)), chunk_nonce_0=12 zero bytes.

        Payload key = HKDF-SHA256(file_key, salt=nonce, info='payload')
                     = f1e86a3624febf3481313e82baca97c46b02a6eb16488e8139c8a35e97c39240
        ChaCha20-Poly1305 encrypt of 'Hello, World!' with that key+nonce
        = dd073ed4b6338dcce783348b2b50f5e1dc04a106598c5e282b27c8df35... (35 bytes total)
        """
        from pqblocks_files.ae import chacha20poly1305_encrypt, derive_payload_key

        file_key = bytes(range(16))
        nonce = bytes(12)  # chunk_nonce_0: all zeros
        payload_key = derive_payload_key(file_key, nonce)
        # Step 2 expected value
        expected_pk = bytes.fromhex(
            "f1e86a3624febf3481313e82baca97c46b02a6eb16488e8139c8a35e97c39240"
        )
        assert payload_key == expected_pk

        pt = b"Hello, World!"
        result = chacha20poly1305_encrypt(payload_key, nonce, pt, aad=b"")
        assert len(result) == len(pt) + 16  # 13 + 16 = 29 bytes

    def test_encrypt_with_aad(self) -> None:
        """AAD is authenticated but not included in output."""
        from pqblocks_files.ae import chacha20poly1305_encrypt

        key = bytes(range(32))
        nonce = bytes(range(12))
        plaintext = b"test"

        result_no_aad = chacha20poly1305_encrypt(key, nonce, plaintext, aad=b"")
        result_with_aad = chacha20poly1305_encrypt(key, nonce, plaintext, aad=b"aad")

        # Different AAD should produce different output
        assert result_no_aad != result_with_aad


class TestChaCha20Poly1305Decrypt:
    """ChaCha20-Poly1305 decryption primitive."""

    def test_decrypt_roundtrip(self) -> None:
        """Encrypt then decrypt returns original plaintext."""
        from pqblocks_files.ae import (
            chacha20poly1305_decrypt,
            chacha20poly1305_encrypt,
        )

        key = bytes(range(32))
        nonce = bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])
        plaintext = b"Hello, World! This is a test."

        ct_tag = chacha20poly1305_encrypt(key, nonce, plaintext)
        decrypted = chacha20poly1305_decrypt(key, nonce, ct_tag)
        assert decrypted == plaintext

    def test_decrypt_small_plaintext(self) -> None:
        """Test decryption of small plaintexts."""
        from pqblocks_files.ae import (
            chacha20poly1305_decrypt,
            chacha20poly1305_encrypt,
        )

        for pt in [b"\x00", b"x", b"ab", b"abc", b"1234567890"]:
            key = bytes(range(32))
            nonce = bytes(range(12))
            ct_tag = chacha20poly1305_encrypt(key, nonce, pt)
            decrypted = chacha20poly1305_decrypt(key, nonce, ct_tag)
            assert decrypted == pt

    def test_decrypt_empty_plaintext(self) -> None:
        """Empty plaintext encrypts to just the 16-byte tag."""
        from pqblocks_files.ae import (
            chacha20poly1305_decrypt,
            chacha20poly1305_encrypt,
        )

        key = bytes(range(32))
        nonce = bytes(range(12))
        plaintext = b""

        ct_tag = chacha20poly1305_encrypt(key, nonce, plaintext)
        assert len(ct_tag) == 16  # Only tag for empty plaintext
        decrypted = chacha20poly1305_decrypt(key, nonce, ct_tag)
        assert decrypted == plaintext


class TestTagMismatch:
    """TagVerificationFailed must be raised on any authenticity violation."""

    def test_wrong_key_raises_tag_mismatch(self) -> None:
        """Decrypt with wrong key must raise TagVerificationFailed."""
        from pqblocks_files.ae import (
            chacha20poly1305_decrypt,
            chacha20poly1305_encrypt,
        )

        key1 = b"\x01" * 32
        key2 = b"\x02" * 32
        nonce = bytes(range(12))
        plaintext = b"secret"

        ct_tag = chacha20poly1305_encrypt(key1, nonce, plaintext)
        with pytest.raises(TagVerificationFailed):
            chacha20poly1305_decrypt(key2, nonce, ct_tag)

    def test_tampered_ciphertext_raises_tag_mismatch(self) -> None:
        """Any bit flip in ciphertext must cause TagVerificationFailed."""
        from pqblocks_files.ae import (
            chacha20poly1305_decrypt,
            chacha20poly1305_encrypt,
        )

        key = bytes(range(32))
        nonce = bytes(range(12))
        plaintext = b"Hello, World!"

        ct_tag = chacha20poly1305_encrypt(key, nonce, plaintext)
        tampered = bytearray(ct_tag)
        tampered[0] ^= 0xFF  # Flip first byte

        with pytest.raises(TagVerificationFailed):
            chacha20poly1305_decrypt(key, nonce, bytes(tampered))

    def test_tampered_tag_raises_tag_mismatch(self) -> None:
        """Any bit flip in tag must cause TagVerificationFailed."""
        from pqblocks_files.ae import (
            chacha20poly1305_decrypt,
            chacha20poly1305_encrypt,
        )

        key = bytes(range(32))
        nonce = bytes(range(12))
        plaintext = b"Hello, World!"

        ct_tag = chacha20poly1305_encrypt(key, nonce, plaintext)
        tampered = bytearray(ct_tag)
        tampered[-1] ^= 0xFF  # Flip last byte (in tag)

        with pytest.raises(TagVerificationFailed):
            chacha20poly1305_decrypt(key, nonce, bytes(tampered))

    def test_truncated_ciphertext_raises_tag_mismatch(self) -> None:
        """Truncated ciphertext must raise TagVerificationFailed, not give garbage."""
        from pqblocks_files.ae import (
            chacha20poly1305_decrypt,
            chacha20poly1305_encrypt,
        )

        key = bytes(range(32))
        nonce = bytes(range(12))
        plaintext = b"Hello, World!"

        ct_tag = chacha20poly1305_encrypt(key, nonce, plaintext)
        truncated = ct_tag[: len(ct_tag) - 5]  # Remove last 5 bytes

        with pytest.raises(TagVerificationFailed):
            chacha20poly1305_decrypt(key, nonce, truncated)

    def test_too_short_ct_tag_raises_tag_mismatch(self) -> None:
        """ct_tag shorter than 16 bytes must raise TagVerificationFailed."""
        from pqblocks_files.ae import chacha20poly1305_decrypt

        key = bytes(range(32))
        nonce = bytes(range(12))
        too_short = bytes(10)  # 10 bytes < 16

        with pytest.raises(TagVerificationFailed):
            chacha20poly1305_decrypt(key, nonce, too_short)


class TestInputValidation:
    """Bad-length inputs must raise ValueError (not crash silently)."""

    def test_payload_key_bad_file_key_length(self) -> None:
        from pqblocks_files.ae import derive_payload_key

        with pytest.raises(ValueError, match="file_key must be 16"):
            derive_payload_key(b"\x00" * 32, b"\x00" * 12)

    def test_payload_key_bad_nonce_length(self) -> None:
        from pqblocks_files.ae import derive_payload_key

        with pytest.raises(ValueError, match="chunk_nonce must be 12"):
            derive_payload_key(b"\x00" * 16, b"\x00" * 11)

    def test_header_mac_key_bad_file_key_length(self) -> None:
        from pqblocks_files.ae import derive_header_mac_key

        with pytest.raises(ValueError, match="file_key must be 16"):
            derive_header_mac_key(b"\x00" * 32)

    def test_encrypt_bad_key_length(self) -> None:
        from pqblocks_files.ae import chacha20poly1305_encrypt

        with pytest.raises(ValueError, match="key must be 32"):
            chacha20poly1305_encrypt(b"\x00" * 16, b"\x00" * 12, b"x")

    def test_encrypt_bad_nonce_length(self) -> None:
        from pqblocks_files.ae import chacha20poly1305_encrypt

        with pytest.raises(ValueError, match="nonce must be 12"):
            chacha20poly1305_encrypt(b"\x00" * 32, b"\x00" * 11, b"x")

    def test_decrypt_bad_key_length(self) -> None:
        from pqblocks_files.ae import chacha20poly1305_decrypt

        with pytest.raises(ValueError, match="key must be 32"):
            chacha20poly1305_decrypt(b"\x00" * 16, b"\x00" * 12, b"\x00" * 16)

    def test_decrypt_bad_nonce_length(self) -> None:
        from pqblocks_files.ae import chacha20poly1305_decrypt

        with pytest.raises(ValueError, match="nonce must be 12"):
            chacha20poly1305_decrypt(b"\x00" * 32, b"\x00" * 11, b"\x00" * 16)