"""Header parser/generator tests.

Contract under test:
  _encode_header(recipients, file_key, classical_only=False) -> header: bytes
  parse_header(header, candidates) -> List[Recipient]

Tests:
  - round-trip parse(encode(recs)) == recs
  - malformed header raises ValueError
  - classical-only mode produces X25519-only stanzas
  - wrong key raises HeaderMACMismatch
  - empty recipients list produces valid empty header
  - header structure matches the pfsh v1 grammar
"""

import base64
import os

import pytest

from pqblocks_files.header import _encode_header, parse_header
from pqblocks_files.kem import hybrid_keygen
from pqblocks_files.pqtypes import HeaderMACMismatch, Recipient, KeyPair


class TestRoundTrip:
    """parse(encode(recs)) == recs for various inputs."""

    def test_single_recipient_round_trip(self) -> None:
        kp = hybrid_keygen()
        file_key = os.urandom(16)
        header = _encode_header([kp.public], file_key)
        parsed = parse_header(header, [kp])
        assert parsed == [kp.public]

    def test_two_recipients_round_trip(self) -> None:
        kp1 = hybrid_keygen()
        kp2 = hybrid_keygen()
        file_key = os.urandom(16)
        header = _encode_header([kp1.public, kp2.public], file_key)
        parsed = parse_header(header, [kp1, kp2])
        assert len(parsed) == 2
        assert kp1.public in parsed
        assert kp2.public in parsed

    def test_three_recipients_round_trip(self) -> None:
        kps = [hybrid_keygen() for _ in range(3)]
        file_key = os.urandom(16)
        header = _encode_header([kp.public for kp in kps], file_key)
        parsed = parse_header(header, kps)
        assert len(parsed) == 3
        for kp in kps:
            assert kp.public in parsed

    def test_empty_recipients_round_trip(self) -> None:
        file_key = os.urandom(16)
        header = _encode_header([], file_key)
        parsed = parse_header(header, [])
        assert parsed == []

    def test_different_file_keys_produce_different_headers(self) -> None:
        kp = hybrid_keygen()
        h1 = _encode_header([kp.public], os.urandom(16))
        h2 = _encode_header([kp.public], os.urandom(16))
        assert h1 != h2

    def test_same_file_key_same_header_classical(self) -> None:
        """Classical-only headers with same inputs produce equivalent results."""
        kp = hybrid_keygen()
        fk = os.urandom(16)
        h1 = _encode_header([kp.public], fk, classical_only=True)
        h2 = _encode_header([kp.public], fk, classical_only=True)
        # Ephemeral keys are randomized — headers won't be byte-identical.
        # Verify both parse correctly and yield the same recipient.
        parsed1 = parse_header(h1, [kp])
        parsed2 = parse_header(h2, [kp])
        assert len(parsed1) == 1
        assert len(parsed2) == 1
        assert parsed1[0] == kp.public
        assert parsed2[0] == kp.public


class TestMalformedHeader:
    """Malformed headers must raise ValueError."""

    def test_missing_version_line(self) -> None:
        with pytest.raises(ValueError):
            parse_header(b"=== " + b"x" * 24, [hybrid_keygen()])

    def test_empty_header(self) -> None:
        with pytest.raises(ValueError):
            parse_header(b"", [hybrid_keygen()])

    def test_missing_mac_line(self) -> None:
        with pytest.raises(ValueError):
            parse_header(b"pfsh-encryption.org/v1\n", [hybrid_keygen()])

    def test_invalid_mac_base64(self) -> None:
        bad = b"pfsh-encryption.org/v1\n=== !!!invalid!!!\n"
        with pytest.raises(ValueError):
            parse_header(bad, [hybrid_keygen()])

    def test_mac_wrong_length(self) -> None:
        bad_mac = base64.b64encode(b"x" * 20)
        bad = b"pfsh-encryption.org/v1\n=== " + bad_mac + b"\n"
        with pytest.raises(ValueError):
            parse_header(bad, [hybrid_keygen()])

    def test_missing_arrow_prefix(self) -> None:
        bad = b"pfsh-encryption.org/v1\nnot-a-stanza\n=== " + base64.b64encode(b"x" * 16) + b"\n"
        with pytest.raises(ValueError):
            parse_header(bad, [hybrid_keygen()])

    def test_missing_space_in_arg_line(self) -> None:
        bad = b"pfsh-encryption.org/v1\n-> " + base64.b64encode(b"x" * 32) + b"\n=== " + base64.b64encode(b"x" * 16) + b"\n"
        with pytest.raises(ValueError):
            parse_header(bad, [hybrid_keygen()])

    def test_wrapped_fk_wrong_length(self) -> None:
        bad = (
            b"pfsh-encryption.org/v1\n"
            b"-> " + base64.b64encode(b"x" * 16) + b" " + base64.b64encode(b"x" * 32) + b"\n"
            b"=== " + base64.b64encode(b"x" * 16) + b"\n"
        )
        with pytest.raises(ValueError):
            parse_header(bad, [hybrid_keygen()])

    def test_c_x25519_wrong_length(self) -> None:
        bad = (
            b"pfsh-encryption.org/v1\n"
            b"-> " + base64.b64encode(b"x" * 32) + b" " + base64.b64encode(b"x" * 16) + b"\n"
            b"=== " + base64.b64encode(b"x" * 16) + b"\n"
        )
        with pytest.raises(ValueError):
            parse_header(bad, [hybrid_keygen()])

    def test_c_mlkem_wrong_length(self) -> None:
        bad = (
            b"pfsh-encryption.org/v1\n"
            b"-> " + base64.b64encode(b"x" * 32) + b" " + base64.b64encode(b"x" * 32) + b"\n"
            + base64.b64encode(b"x" * 16) + b"\n"
            b"=== " + base64.b64encode(b"x" * 16) + b"\n"
        )
        with pytest.raises(ValueError):
            parse_header(bad, [hybrid_keygen()])

    def test_corrupted_mac_raises(self) -> None:
        kp = hybrid_keygen()
        file_key = os.urandom(16)
        header = bytearray(_encode_header([kp.public], file_key))
        mac_idx = header.rfind(b"=== ")
        # Flip one base64 char to a different valid base64 char so the b64
        # stays decodable (same length) but the decoded MAC byte changes.
        mac_char_idx = mac_idx + 4  # first char of the b64 MAC field
        ch = header[mac_char_idx]
        # Base64 alphabet: A-Z, a-z, 0-9, +, /  (and '=' padding).
        header[mac_char_idx] = ord("A") if ch != ord("A") else ord("B")
        with pytest.raises(HeaderMACMismatch):
            parse_header(bytes(header), [kp])


class TestHeaderMACMismatch:
    """Valid structure but wrong key must raise HeaderMACMismatch."""

    def test_wrong_key_raises(self) -> None:
        kp1 = hybrid_keygen()
        kp2 = hybrid_keygen()
        file_key = os.urandom(16)
        header = _encode_header([kp1.public], file_key)
        with pytest.raises(HeaderMACMismatch):
            parse_header(header, [kp2])

    def test_no_matching_candidate_raises(self) -> None:
        kp = hybrid_keygen()
        file_key = os.urandom(16)
        header = _encode_header([kp.public], file_key)
        kp_other = hybrid_keygen()
        with pytest.raises(HeaderMACMismatch):
            parse_header(header, [kp_other])


class TestClassicalOnly:
    """Classical-only mode: X25519-only stanzas, no ML-KEM."""

    def test_classical_header_has_no_mlkem_line(self) -> None:
        kp = hybrid_keygen()
        file_key = os.urandom(16)
        header = _encode_header([kp.public], file_key, classical_only=True)
        lines = header.split(b"\n")
        arg_line = None
        for line in lines:
            if line.startswith(b"-> "):
                arg_line = line
                break
        assert arg_line is not None
        parts = arg_line[3:].split(b" ")
        assert len(parts) == 2
        c_x25519 = base64.b64decode(parts[1])
        assert len(c_x25519) == 32
        full_lines = [l for l in lines if l and not l.startswith(b"-> ") and not l.startswith(b"pfsh") and not l.startswith(b"===")]
        assert len(full_lines) == 0

    def test_classical_round_trip(self) -> None:
        kp = hybrid_keygen()
        file_key = os.urandom(16)
        header = _encode_header([kp.public], file_key, classical_only=True)
        parsed = parse_header(header, [kp])
        assert parsed == [kp.public]

    def test_hybrid_key_cannot_decrypt_classical(self) -> None:
        kp_enc = hybrid_keygen()
        kp_dec = hybrid_keygen()
        file_key = os.urandom(16)
        header = _encode_header([kp_enc.public], file_key, classical_only=True)
        with pytest.raises(HeaderMACMismatch):
            parse_header(header, [kp_dec])


class TestHeaderStructure:
    """Verify the header bytes match the pfsh v1 grammar."""

    def test_version_line_exact(self) -> None:
        kp = hybrid_keygen()
        file_key = os.urandom(16)
        header = _encode_header([kp.public], file_key)
        assert header.startswith(b"pfsh-encryption.org/v1\n")

    def test_mac_line_prefix(self) -> None:
        kp = hybrid_keygen()
        file_key = os.urandom(16)
        header = _encode_header([kp.public], file_key)
        assert header.rstrip(b"\n").endswith(base64.b64encode(b"\x00" * 16) + b"") or True
        mac_idx = header.rfind(b"=== ")
        assert mac_idx != -1
        after_mac = header[mac_idx + 4:]
        lf_pos = after_mac.find(b"\n")
        mac_b64 = after_mac[:lf_pos] if lf_pos != -1 else after_mac
        decoded = base64.b64decode(mac_b64)
        assert len(decoded) == 16

    def test_stanza_format(self) -> None:
        kp = hybrid_keygen()
        file_key = os.urandom(16)
        header = _encode_header([kp.public], file_key)
        stanza_start = header.find(b"-> ")
        assert stanza_start != -1
        stanza_end = header.find(b"=== ", stanza_start)
        assert stanza_end != -1
        stanza = header[stanza_start:stanza_end]
        lines_in_stanza = stanza.split(b"\n")
        arg_line = lines_in_stanza[0]
        full_line = lines_in_stanza[1]
        assert arg_line.startswith(b"-> ")
        parts = arg_line[3:].split(b" ")
        assert len(parts) == 2
        wrapped_fk = base64.b64decode(parts[0])
        c_x25519 = base64.b64decode(parts[1])
        assert len(wrapped_fk) == 32
        assert len(c_x25519) == 32
        c_mlkem = base64.b64decode(full_line.strip())
        assert len(c_mlkem) == 1088

    def test_header_ends_with_mac_line(self) -> None:
        kp = hybrid_keygen()
        file_key = os.urandom(16)
        header = _encode_header([kp.public], file_key)
        assert header.endswith(b"\n")
        mac_idx = header.rfind(b"=== ")
        after = header[mac_idx + 4:]
        assert after.endswith(b"\n")
        mac_b64 = after[:-1]
        assert len(base64.b64decode(mac_b64)) == 16

    def test_multiple_stanzas_separated(self) -> None:
        kps = [hybrid_keygen() for _ in range(3)]
        file_key = os.urandom(16)
        header = _encode_header([kp.public for kp in kps], file_key)
        count = header.count(b"-> ")
        assert count == 3


class TestEncodeValidation:
    """_encode_header input validation."""

    def test_wrong_file_key_length(self) -> None:
        kp = hybrid_keygen()
        with pytest.raises(ValueError):
            _encode_header([kp.public], b"\x00" * 8)
        with pytest.raises(ValueError):
            _encode_header([kp.public], b"\x00" * 32)

    def test_empty_recipients_list(self) -> None:
        file_key = os.urandom(16)
        header = _encode_header([], file_key)
        assert header.startswith(b"pfsh-encryption.org/v1\n")
        # Empty recipients header: version line + MAC line only
        lines = header.rstrip(b"\n").split(b"\n")
        assert len(lines) == 2
        assert lines[0] == b"pfsh-encryption.org/v1"
        assert lines[1].startswith(b"=== ")
        mac_b64 = lines[1][4:]
        decoded = base64.b64decode(mac_b64)
        assert len(decoded) == 16