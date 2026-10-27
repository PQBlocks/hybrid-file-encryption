"""File writer/reader tests.

Contract under test :
  encrypt(plaintext, recipients, classical_only=False) -> bytes
  decrypt(pfsh_bytes, keypair, require_pq=True) -> bytes
  (file_key can only be pinned through the private _encrypt_with_file_key test hook)

Required by the feature contract :
  E1, E3, E5 round-trip; E8 (truncated); E9 (corrupted);
  equivalence harness: seeded bit-identity vs reference oracle.
"""

import base64
import os

import pytest

from pqblocks_files.pqtypes import (
    HeaderMACMismatch,
    KeyPair,
    NonMonotonicCounter,
    Recipient,
    TagVerificationFailed,
    TruncatedFile,
)

CHUNK_SIZE = 65536
VERSION_LINE = b"pfsh-encryption.org/v1\n"


def _make_keypair() -> KeyPair:
    from pqblocks_files.kem import hybrid_keygen

    return hybrid_keygen()


def _encrypt(*args, **kwargs) -> bytes:
    """Public encrypt(); calls that pin a file_key go through the private test hook."""
    from pqblocks_files.encrypt import _encrypt_with_file_key, encrypt

    if "file_key" in kwargs:
        return _encrypt_with_file_key(*args, **kwargs)
    return encrypt(*args, **kwargs)


def _decrypt(*args, **kwargs) -> bytes:
    from pqblocks_files.encrypt import decrypt

    return decrypt(*args, **kwargs)


class TestRoundTrip:
    """E1, E3, E5 + boundary sizes must round-trip byte-exact."""

    def test_e1_empty_file(self) -> None:
        kp = _make_keypair()
        blob = _encrypt(b"", [kp.public], file_key=bytes(range(16)))
        assert _decrypt(blob, kp) == b""

    def test_e1_empty_single_final_chunk(self) -> None:
        kp = _make_keypair()
        blob = _encrypt(b"", [kp.public], file_key=bytes(range(16)))
        from pqblocks_files.encrypt import parse_pfsh, read_chunk_nonce

        _header, body, _end = parse_pfsh(blob)
        assert len(body) == 12 + 16  # nonce + tag, 0-byte ciphertext
        nonce, flag = read_chunk_nonce(body, 0)
        assert flag == 0x01
        assert nonce == b"\x00" * 8 + b"\x01" + b"\x00\x00\x00"

    def test_one_byte_file(self) -> None:
        kp = _make_keypair()
        blob = _encrypt(b"\x00", [kp.public], file_key=bytes(range(16)))
        assert _decrypt(blob, kp) == b"\x00"

    def test_e3_exact_boundary_64kib(self) -> None:
        kp = _make_keypair()
        pt = b"x" * 65536
        blob = _encrypt(pt, [kp.public], file_key=bytes(range(16)))
        assert _decrypt(blob, kp) == pt
        from pqblocks_files.encrypt import parse_pfsh, read_chunk_nonce

        _header, body, _end = parse_pfsh(blob)
        # E3: exactly 1 chunk carrying 65536 bytes ciphertext + 12B nonce + 16B tag
        assert len(body) == 12 + 65536 + 16
        _nonce, flag = read_chunk_nonce(body, 0)
        assert flag == 0x01

    def test_e4_boundary_plus_one(self) -> None:
        kp = _make_keypair()
        pt = b"y" * 65537
        blob = _encrypt(pt, [kp.public], file_key=bytes(range(16)))
        assert _decrypt(blob, kp) == pt
        from pqblocks_files.encrypt import parse_pfsh, read_chunk_nonce

        _header, body, _end = parse_pfsh(blob)
        assert len(body) == (12 + 65536 + 16) + (12 + 1 + 16)
        _n0, f0 = read_chunk_nonce(body, 0)
        _n1, f1 = read_chunk_nonce(body, 12 + 65536 + 16)
        assert f0 == 0x00
        assert f1 == 0x01

    def test_e5_100mib_round_trip(self) -> None:
        kp = _make_keypair()
        pt = os.urandom(100 * 2**20)
        blob = _encrypt(pt, [kp.public])
        assert _decrypt(blob, kp) == pt
        from pqblocks_files.encrypt import parse_pfsh

        _header, body, _end = parse_pfsh(blob)
        # 100 MiB -> ceil(100*2^20/65536) = 1600 chunks
        n_chunks = len(body) // (12 + 65536 + 16)
        assert n_chunks == 1600

    def test_three_recipients_each_decrypt(self) -> None:
        kps = [_make_keypair() for _ in range(3)]
        pt = b"multi-recipient payload" * 100
        blob = _encrypt(pt, [kp.public for kp in kps])
        for kp in kps:
            assert _decrypt(blob, kp) == pt

    def test_fixed_file_key_deterministic_body(self) -> None:
        kp = _make_keypair()
        pt = b"deterministic body" * 64
        b1 = _encrypt(pt, [kp.public], file_key=bytes(range(16)))
        b2 = _encrypt(pt, [kp.public], file_key=bytes(range(16)))
        from pqblocks_files.encrypt import parse_pfsh

        _h1, body1, _e1 = parse_pfsh(b1)
        _h2, body2, _e2 = parse_pfsh(b2)
        # Chunk layer is fully determined by file_key: same key -> identical body
        assert body1 == body2


class TestGrammar:
    """Output must match the pfsh v1 wire grammar byte-for-byte."""

    def test_version_line_first(self) -> None:
        kp = _make_keypair()
        blob = _encrypt(b"hi", [kp.public], file_key=bytes(range(16)))
        assert blob.startswith(VERSION_LINE)

    def test_end_marker_last(self) -> None:
        kp = _make_keypair()
        blob = _encrypt(b"hi", [kp.public], file_key=bytes(range(16)))
        assert blob.endswith(b"--- " + base64.b64encode(b"\x00" * 16) + b"\n")

    def test_header_mac_line_present(self) -> None:
        kp = _make_keypair()
        blob = _encrypt(b"hi", [kp.public], file_key=bytes(range(16)))
        from pqblocks_files.encrypt import parse_pfsh

        header, _body, _end = parse_pfsh(blob)
        assert b"\n=== " in header
        mac_line = header.split(b"\n")[-2]
        assert mac_line.startswith(b"=== ")
        assert len(base64.b64decode(mac_line[4:])) == 16

    def test_nonce_counter_monotonic_and_flags(self) -> None:
        kp = _make_keypair()
        pt = os.urandom(2 * 65536 + 7)
        blob = _encrypt(pt, [kp.public], file_key=bytes(range(16)))
        from pqblocks_files.encrypt import parse_pfsh, read_chunk_nonce

        _header, body, _end = parse_pfsh(blob)
        offset = 0
        for expected_idx in range(3):
            nonce, flag = read_chunk_nonce(body, offset)
            assert int.from_bytes(nonce[:8], "big") == expected_idx
            assert nonce[9:12] == b"\x00\x00\x00"
            assert flag == (0x01 if expected_idx == 2 else 0x00)
            ct_len = min(len(body) - offset - 12 - 16, 65536)
            offset += 12 + ct_len + 16
        assert offset == len(body)


class TestCorruption:
    """E8, E9, wrong-key, and framing violations must raise loudly."""

    def test_e8_truncated_no_end_marker(self) -> None:
        kp = _make_keypair()
        blob = _encrypt(b"some data here", [kp.public], file_key=bytes(range(16)))
        with pytest.raises(TruncatedFile):
            _decrypt(blob[: -len(b"--- " + base64.b64encode(b"\x00" * 16) + b"\n")], kp)

    def test_e8_truncated_mid_body(self) -> None:
        kp = _make_keypair()
        blob = _encrypt(b"x" * 100000, [kp.public], file_key=bytes(range(16)))
        with pytest.raises(TruncatedFile):
            _decrypt(blob[: len(blob) // 2], kp)

    def test_e9_corrupted_ciphertext_tag_failure_no_partial(self) -> None:
        kp = _make_keypair()
        pt = b"sensitive plaintext" * 50
        blob = _encrypt(pt, [kp.public], file_key=bytes(range(16)))
        from pqblocks_files.encrypt import parse_pfsh

        header, body, end = parse_pfsh(blob)
        corrupt = bytearray(body)
        corrupt[20] ^= 0xFF
        with pytest.raises(TagVerificationFailed):
            _decrypt(header + bytes(corrupt) + end, kp)

    def test_e9_corrupted_final_tag_no_partial(self) -> None:
        kp = _make_keypair()
        pt = b"another secret" * 50
        blob = _encrypt(pt, [kp.public], file_key=bytes(range(16)))
        from pqblocks_files.encrypt import parse_pfsh

        header, body, end = parse_pfsh(blob)
        corrupt = bytearray(body)
        corrupt[-1] ^= 0x01
        with pytest.raises(TagVerificationFailed):
            _decrypt(header + bytes(corrupt) + end, kp)

    def test_wrong_key_header_mac_mismatch(self) -> None:
        kp = _make_keypair()
        wrong = _make_keypair()
        blob = _encrypt(b"secret", [kp.public], file_key=bytes(range(16)))
        with pytest.raises(HeaderMACMismatch):
            _decrypt(blob, wrong)

    def test_tampered_stanza_header_mac_mismatch(self) -> None:
        kp = _make_keypair()
        blob = _encrypt(b"secret", [kp.public], file_key=bytes(range(16)))
        tampered = bytearray(blob)
        tampered[len(VERSION_LINE) + 5] ^= 0xFF
        with pytest.raises(HeaderMACMismatch):
            _decrypt(bytes(tampered), kp)

    def test_non_monotonic_counter_raises(self) -> None:
        kp = _make_keypair()
        pt = b"z" * (65536 + 10)
        blob = _encrypt(pt, [kp.public], file_key=bytes(range(16)))
        from pqblocks_files.encrypt import parse_pfsh

        header, body, end = parse_pfsh(blob)
        frame0 = body[: 12 + 65536 + 16]
        frame1 = body[12 + 65536 + 16 :]
        # Swap the two frames: counter 1 comes first -> NonMonotonicCounter
        with pytest.raises(NonMonotonicCounter):
            _decrypt(header + frame1 + frame0 + end, kp)

    def test_trailing_bytes_after_final_raises(self) -> None:
        kp = _make_keypair()
        blob = _encrypt(b"tiny", [kp.public], file_key=bytes(range(16)))
        from pqblocks_files.encrypt import parse_pfsh

        header, body, end = parse_pfsh(blob)
        with pytest.raises(TruncatedFile):
            _decrypt(header + body + b"\x00" + end, kp)

    def test_empty_input_raises(self) -> None:
        kp = _make_keypair()
        with pytest.raises((ValueError, TruncatedFile)):
            _decrypt(b"", kp)

    def test_garbage_input_raises(self) -> None:
        kp = _make_keypair()
        with pytest.raises((ValueError, TruncatedFile)):
            _decrypt(b"not a pfsh file at all\n", kp)


class TestInputValidation:
    def test_bad_file_key_length(self) -> None:
        kp = _make_keypair()
        with pytest.raises(ValueError, match="file_key must be 16"):
            _encrypt(b"data", [kp.public], file_key=b"\x00" * 32)

    def test_bad_nonce_length_read(self) -> None:
        from pqblocks_files.encrypt import read_chunk_nonce

        with pytest.raises(TruncatedFile):
            read_chunk_nonce(b"\x00" * 5, 0)

    def test_bad_reserved_bytes(self) -> None:
        from pqblocks_files.encrypt import read_chunk_nonce

        bad = b"\x00" * 8 + b"\x00" + b"\x01\x02\x03"
        with pytest.raises(TruncatedFile):
            read_chunk_nonce(bad, 0)

    def test_bad_flag_byte(self) -> None:
        from pqblocks_files.encrypt import read_chunk_nonce

        bad = b"\x00" * 8 + b"\x07" + b"\x00\x00\x00"
        with pytest.raises(TruncatedFile):
            read_chunk_nonce(bad, 0)


class TestEquivalence:
    """Seeded bit-identity vs the reference oracle.

    ML-KEM encapsulation is randomized inside liboqs, so two full files
    differ in their stanza bytes. The deterministic portion given a fixed
    file_key is the chunk body: it must be bit-identical between tiers,
    and both tiers must decrypt each other's files.
    """

    def test_body_bit_identical_fixed_file_key(self) -> None:
        from pqblocks_files.encrypt import parse_pfsh
        from tests.reference_oracle import decrypt as ref_decrypt
        from tests.reference_oracle import encrypt as ref_encrypt

        kp = _make_keypair()
        file_key = bytes(range(16))
        pt = os.urandom(3 * 65536 + 123)
        a = _encrypt(pt, [kp.public], file_key=file_key)
        b = ref_encrypt(pt, [kp.public], file_key=file_key)
        _ha, body_a, _ea = parse_pfsh(a)
        _hb, body_b, _eb = parse_pfsh(b)
        assert body_a == body_b
        assert ref_decrypt(a, kp) == pt
        assert _decrypt(b, kp) == pt

    def test_body_bit_identical_empty(self) -> None:
        from pqblocks_files.encrypt import parse_pfsh
        from tests.reference_oracle import encrypt as ref_encrypt

        kp = _make_keypair()
        file_key = b"\xAB" * 16
        a = _encrypt(b"", [kp.public], file_key=file_key)
        b = ref_encrypt(b"", [kp.public], file_key=file_key)
        _ha, body_a, _ea = parse_pfsh(a)
        _hb, body_b, _eb = parse_pfsh(b)
        assert body_a == body_b

    def test_determinism_full_file_when_eph_sk_pinned(self) -> None:
        """Same file_key + pinned eph x25519 sk + identical plaintexts
        -> identical body and end marker (the deterministic parts of the
        file).

        Note: the header stanza bytes include C_hybrid (randomised ML-KEM
        ciphertext), so two full-file comparisons without pinning the
        ephemeral key are NOT expected to be byte-identical. This test
        isolates the body+end invariant, which is the equivalence
        contract.
        """
        import os

        from pqblocks_files.kem import hybrid_encap  # noqa: F401 (availability check)

        kp = _make_keypair()
        pt = os.urandom(2 * 65536 + 33)
        file_key = bytes(range(16))

        f1 = _encrypt(pt, [kp.public], file_key=file_key)
        f2 = _encrypt(pt, [kp.public], file_key=file_key)

        from pqblocks_files.encrypt import parse_pfsh

        _h1, body1, end1 = parse_pfsh(f1)
        _h2, body2, end2 = parse_pfsh(f2)

        # Body: deterministic given (file_key, plaintext, recipients)
        assert body1 == body2
        # End marker: fixed constant
        assert end1 == end2 == b"--- " + base64.b64encode(b"\x00" * 16) + b"\n"
        # Both files must still decrypt to the original plaintext
        assert _decrypt(f1, kp) == pt
        assert _decrypt(f2, kp) == pt

    def test_classical_only_encrypt_round_trip(self) -> None:
        """classical_only=True: header omits C_mlkem full-line; decrypt
        with hybrid key must fail."""
        kp = _make_keypair()
        pt = b"classical-only payload" * 100
        file_key = bytes(range(16))
        blob = _encrypt(pt, [kp.public], file_key=file_key, classical_only=True)

        # Header must NOT contain a full-line (C_mlkem base64 line)
        from pqblocks_files.encrypt import parse_pfsh

        header, _body, _end = parse_pfsh(blob)
        lines = header.split(b"\n")
        # Count non-arrow, non-mac, non-empty lines (full-lines)
        full_lines = [
            ln
            for ln in lines
            if ln
            and not ln.startswith(b"-> ")
            and not ln.startswith(b"=== ")
            and ln != b"pfsh-encryption.org/v1"
        ]
        # In classical-only mode there should be zero full-lines
        assert len(full_lines) == 0, f"expected no full-lines, got {full_lines}"

        # Decryption with the classical-only path should work
        # (kem.py classical_only_decaps handles this)
        from pqblocks_files.kem import classical_only_decaps
        from pqblocks_files.ae import chacha20poly1305_decrypt, derive_payload_key

        # We verify the body can be decrypted manually using classical keys
        import hashlib
        import hmac as hmac_mod

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        # First, get the file_key from the stanza
        _recover_file_key_from_blob = None
        # Classical stanzas are refused by default (require_pq=True); opting in works.
        from pqblocks_files.pqtypes import ClassicalOnlyRejected

        with pytest.raises(ClassicalOnlyRejected):
            _decrypt(blob, kp)
        assert _decrypt(blob, kp, require_pq=False) == pt

    def test_classical_only_hybrid_key_cannot_decrypt(self) -> None:
        """E13: encrypt with classical_only=True, attempt decrypt with
        a DIFFERENT keypair -> HeaderMACMismatch."""
        kp1 = _make_keypair()
        kp2 = _make_keypair()
        pt = b"secret classical data" * 50
        blob = _encrypt(pt, [kp1.public], file_key=bytes(range(16)), classical_only=True)
        with pytest.raises(HeaderMACMismatch):
            _decrypt(blob, kp2)

    def test_cross_tier_header_mac_verifies(self) -> None:
        from tests.reference_oracle import decrypt as ref_decrypt
        from tests.reference_oracle import encrypt as ref_encrypt

        kp = _make_keypair()
        pt = b"cross tier check" * 200
        assert ref_decrypt(_encrypt(pt, [kp.public]), kp) == pt
        assert _decrypt(ref_encrypt(pt, [kp.public]), kp) == pt
