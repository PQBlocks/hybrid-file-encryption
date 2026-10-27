"""Chunker tests.

Contract under test:
  _chunk(plaintext: bytes, file_key: bytes (16B)) -> list[(nonce: bytes (12B), chunk: bytes)]

Where chunk = ciphertext || tag (16B Poly1305 tag)
- Chunks are 64 KiB max (65536 bytes ciphertext)
- Nonce structure (12 bytes):
  - Bytes 0-7: big-endian 64-bit chunk counter (starting at 0)
  - Byte 8: 0x00 (non-final) or 0x01 (final chunk)
  - Bytes 9-11: reserved, MUST be 0x00
- Encryption: payload_key_i = HKDF-SHA256(file_key, salt=chunk_nonce_i, info="payload")
- ChaCha20-Poly1305(key=payload_key_i, nonce=chunk_nonce_i, pt) -> ct || tag
"""

import os

import pytest

from pqblocks_files.chunker import _chunk, _unchunk


class TestEmptyFile:
    """E1: Empty file (0 bytes) must produce 1 chunk with 0-byte ciphertext."""

    def test_empty_file_one_chunk(self) -> None:
        """Empty file → 1 chunk, 16-byte tag only (0-byte ciphertext + 16-byte tag)."""
        file_key = os.urandom(16)
        result = _chunk(b"", file_key)
        assert len(result) == 1
        nonce, ct_and_tag = result[0]
        assert len(nonce) == 12
        assert len(ct_and_tag) == 16  # 0-byte plaintext + 16-byte tag
        assert nonce[8] == 0x01  # final flag
        assert nonce[9:12] == b"\x00\x00\x00"  # reserved bytes

    def test_empty_file_nonce_counter_zero(self) -> None:
        """Empty file chunk nonce has counter=0."""
        file_key = os.urandom(16)
        nonce, _ = _chunk(b"", file_key)[0]
        assert nonce[:8] == b"\x00" * 8  # counter = 0


class TestOneByteFile:
    """E2: 1-byte file must produce 1 chunk with 1-byte ciphertext."""

    def test_one_byte_file_single_chunk(self) -> None:
        """1-byte file → 1 chunk, 1-byte ciphertext, final flag=0x01."""
        file_key = os.urandom(16)
        result = _chunk(b"\x00", file_key)
        assert len(result) == 1
        nonce, ct_and_tag = result[0]
        assert len(ct_and_tag) == 1 + 16  # 1 byte plaintext + 16 byte tag
        assert nonce[8] == 0x01  # final flag


class TestExactBoundary:
    """E3: 64 KiB file (exact boundary) must produce 1 chunk."""

    def test_exact_64k_minus_one(self) -> None:
        """65535 bytes → 1 chunk, 65535 bytes ciphertext + tag."""
        file_key = os.urandom(16)
        plaintext = b"x" * 65535
        result = _chunk(plaintext, file_key)
        assert len(result) == 1
        nonce, ct_and_tag = result[0]
        assert len(ct_and_tag) == 65535 + 16
        assert nonce[8] == 0x01  # final flag

    def test_exact_64k(self) -> None:
        """E3: 65536 bytes → exactly 1 chunk, final flag=0x01."""
        file_key = os.urandom(16)
        plaintext = b"x" * 65536
        result = _chunk(plaintext, file_key)
        assert len(result) == 1
        nonce, ct_and_tag = result[0]
        assert len(ct_and_tag) == 65536 + 16
        assert nonce[8] == 0x01  # final flag


class TestJustOverBoundary:
    """E4: 64 KiB + 1 file must produce 2 chunks."""

    def test_64k_plus_one(self) -> None:
        """65537 bytes → 2 chunks: full non-final + 1-byte final."""
        file_key = os.urandom(16)
        plaintext = b"x" * 65537
        result = _chunk(plaintext, file_key)
        assert len(result) == 2
        # First chunk: non-final
        nonce0, ct_and_tag0 = result[0]
        assert len(ct_and_tag0) == 65536 + 16
        assert nonce0[8] == 0x00  # non-final flag
        assert nonce0[:8] == b"\x00" * 8  # counter = 0
        # Second chunk: final
        nonce1, ct_and_tag1 = result[1]
        assert len(ct_and_tag1) == 1 + 16  # 1 byte plaintext + tag
        assert nonce1[8] == 0x01  # final flag
        assert nonce1[:8] == (1).to_bytes(8, "big")  # counter = 1


class TestLargeFile:
    """E5: 100 MB file → 1600 chunks. Uses 1 MB for test speed."""

    def test_large_file_chunk_count_formula(self) -> None:
        """Verify chunk count formula: ceil(N / 65536)."""
        file_key = os.urandom(16)
        # Use 1 MB for speed, verify formula
        # ceil(100 MiB / 64 KiB) = ceil(104857600 / 65536) = 1600
        plaintext = os.urandom(100 * 1024 * 1024)
        result = _chunk(plaintext, file_key)
        assert len(result) == 1600
        # Verify last chunk is final
        nonce_last, _ = result[-1]
        assert nonce_last[8] == 0x01  # final flag


class TestNonceStructure:
    """Byte-level verification of nonce structure."""

    def test_nonce_counter_increments(self) -> None:
        """Each chunk's counter increments by 1."""
        file_key = os.urandom(16)
        plaintext = b"x" * (65536 * 3 + 100)  # 3 full chunks + 100 bytes
        result = _chunk(plaintext, file_key)
        assert len(result) == 4
        for i, (nonce, _) in enumerate(result):
            expected_counter = i.to_bytes(8, "big")
            assert nonce[:8] == expected_counter, f"counter mismatch at chunk {i}"

    def test_nonce_reserved_bytes_zero(self) -> None:
        """Bytes 9-11 of nonce are always 0x00."""
        file_key = os.urandom(16)
        result = _chunk(b"x" * 200000, file_key)
        for nonce, _ in result:
            assert nonce[9:12] == b"\x00\x00\x00"


class TestChunkFlag:
    """Verify 0x00/0x01 flags for non-final/final chunks."""

    def test_all_non_final_have_zero_flag(self) -> None:
        """All chunks except the last have flag=0x00."""
        file_key = os.urandom(16)
        plaintext = b"x" * (65536 * 5 + 1000)  # 6 chunks
        result = _chunk(plaintext, file_key)
        for nonce, _ in result[:-1]:
            assert nonce[8] == 0x00  # non-final

    def test_last_chunk_has_one_flag(self) -> None:
        """Final chunk has flag=0x01."""
        file_key = os.urandom(16)
        result = _chunk(b"x" * 1000, file_key)  # 1 chunk, final
        for nonce, _ in result[-1:]:
            assert nonce[8] == 0x01


class TestRoundTrip:
    """Round-trip chunking and reassembly."""

    def test_round_trip_preserves_plaintext(self) -> None:
        """chunk then _unchunk must return original plaintext."""
        file_key = os.urandom(16)
        for size in [0, 1, 100, 65535, 65536, 65537, 100000, 1000000]:
            plaintext = os.urandom(size)
            chunked = _chunk(plaintext, file_key)
            reconstructed = _unchunk(chunked, file_key)
            assert reconstructed == plaintext, f"round-trip failed for size {size}"

    def test_round_trip_with_seeded_nonce(self) -> None:
        """Deterministic chunks with seeded nonce produce identical output."""
        file_key = b"\x00" * 16  # deterministic key
        plaintext = b"\x01" * 1000
        result1 = _chunk(plaintext, file_key)
        result2 = _chunk(plaintext, file_key)
        assert result1 == result2  # bit-identical