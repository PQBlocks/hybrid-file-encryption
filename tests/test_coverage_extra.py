"""Extra coverage: tests for previously uncovered paths in kem.py,
reference_oracle.py, and cli.py.
"""

import io
import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pqblocks_files import cli
from pqblocks_files.kem import (
    _derive_x25519_sk,
    classical_only_encap,
    hybrid_encap,
    hybrid_keygen,
)
from tests.reference_oracle import (
    _END_MARKER,
    _VERSION_LINE,
    _split_file,
    decrypt,
    encrypt,
)
from pqblocks_files.keys import keygen, save_private_key, save_public_key
from tests.cli_pass import TEST_PASSPHRASE, with_passphrase
from pqblocks_files.pqtypes import HeaderMACMismatch, KeyPair, Recipient, TruncatedFile


def _run_cli(argv, stdin_bytes=b""):
    mock_in = type("MIn", (), {"buffer": io.BytesIO(stdin_bytes)})()
    mock_out = type("MOut", (), {"buffer": io.BytesIO()})()
    mock_out.buffer = io.BytesIO()
    with patch("sys.stdin", mock_in), patch("sys.stdout", mock_out):
        rc = cli.main(with_passphrase(argv))
        out_bytes = mock_out.buffer.getvalue()
    return rc, out_bytes


def _make_pair(tmp_path, prefix="cov"):
    kp = keygen()
    pub = str(tmp_path / f"{prefix}_pub.sec")
    priv = str(tmp_path / f"{prefix}_priv.sec")
    save_public_key(kp, pub)
    save_private_key(kp, priv, TEST_PASSPHRASE)
    return pub, priv, kp


class TestKemCoverage:
    def test_derive_x25519_sk_returns_32_bytes(self):
        result = _derive_x25519_sk(b"some input material")
        assert len(result) == 32

    def test_hybrid_encap_rejects_invalid_ephemeral_32byte(self):
        kp = hybrid_keygen()
        with pytest.raises(ValueError):
            hybrid_encap(kp.public.hybrid_pk, b"\x00" * 31)

    def test_classical_only_encap_rejects_invalid_ephemeral_32byte(self):
        kp = hybrid_keygen()
        x25519_pk = kp.public.hybrid_pk[1184:]
        with pytest.raises(ValueError):
            classical_only_encap(x25519_pk, b"\x00" * 31)


class TestReferenceOracleCoverage:
    def test_encrypt_classical_only_raises(self):
        with pytest.raises(ValueError, match="hybrid mode only"):
            encrypt(b"test", [], classical_only=True)

    def test_encrypt_bad_file_key_length(self):
        kp = keygen()
        with pytest.raises(ValueError, match="file_key must be 16"):
            encrypt(
                b"test",
                [Recipient(hybrid_pk=kp.public.hybrid_pk)],
                file_key=b"\x00" * 32,
            )

    def test_split_file_missing_version(self):
        with pytest.raises(ValueError, match="version line"):
            _split_file(b"no version here")

    def test_split_file_missing_end_marker(self):
        data = _VERSION_LINE + b"=== abc\n"
        with pytest.raises(TruncatedFile, match="end marker"):
            _split_file(data)

    def test_decrypt_no_matching_stanza(self):
        kp = keygen()
        kp2 = keygen()
        file_key = b"\x00" * 16
        enc = encrypt(
            b"secret",
            [Recipient(hybrid_pk=kp.public.hybrid_pk)],
            file_key=file_key,
        )
        bad_kp = KeyPair(
            public=Recipient(hybrid_pk=b"\x00" * 1216),
            private=kp2.private,
        )
        with pytest.raises(HeaderMACMismatch):
            decrypt(enc, bad_kp)

    def test_decrypt_short_chunk_frame(self):
        kp = keygen()
        file_key = b"\x00" * 16
        enc = encrypt(
            b"secret",
            [Recipient(hybrid_pk=kp.public.hybrid_pk)],
            file_key=file_key,
        )
        header, _ = _split_file(enc)
        short_body = b"\x00" * 20
        data = header + short_body + _END_MARKER
        kp_full = KeyPair(
            public=Recipient(hybrid_pk=kp.public.hybrid_pk),
            private=kp.private,
        )
        with pytest.raises(TruncatedFile, match="short chunk frame"):
            decrypt(data, kp_full)

    def test_decrypt_short_non_final_chunk(self):
        kp = keygen()
        file_key = b"\x00" * 16
        enc = encrypt(
            b"secret",
            [Recipient(hybrid_pk=kp.public.hybrid_pk)],
            file_key=file_key,
        )
        header, _ = _split_file(enc)
        nonce = b"\x00" * 8 + b"\x00" + b"\x00\x00\x00"
        take = 100
        ct_tag = b"\x00" * (take + 16)
        short_body = nonce + ct_tag
        data = header + short_body + _END_MARKER
        kp_full = KeyPair(
            public=Recipient(hybrid_pk=kp.public.hybrid_pk),
            private=kp.private,
        )
        with pytest.raises(TruncatedFile, match="short non-final chunk"):
            decrypt(data, kp_full)

    def test_decrypt_trailing_bytes_after_final(self):
        kp = keygen()
        file_key = b"\x00" * 16
        plaintext = b"tiny"
        enc = encrypt(
            plaintext,
            [Recipient(hybrid_pk=kp.public.hybrid_pk)],
            file_key=file_key,
        )
        header, body = _split_file(enc)
        data = header + body + b"\x00" * 5 + _END_MARKER
        kp_full = KeyPair(
            public=Recipient(hybrid_pk=kp.public.hybrid_pk),
            private=kp.private,
        )
        with pytest.raises(TruncatedFile, match="trailing bytes"):
            decrypt(data, kp_full)

    def test_decrypt_no_final_chunk(self):
        kp = keygen()
        file_key = b"\x00" * 16
        enc = encrypt(
            b"secret",
            [Recipient(hybrid_pk=kp.public.hybrid_pk)],
            file_key=file_key,
        )
        header, _ = _split_file(enc)
        data = header + b"" + _END_MARKER
        kp_full = KeyPair(
            public=Recipient(hybrid_pk=kp.public.hybrid_pk),
            private=kp.private,
        )
        with pytest.raises(TruncatedFile, match="no final chunk"):
            decrypt(data, kp_full)


class TestCliCoverage:
    def test_encrypt_from_file_path(self, tmp_path):
        pub, _, _ = _make_pair(tmp_path, "filepath")
        input_file = str(tmp_path / "input.txt")
        with open(input_file, "wb") as f:
            f.write(b"file input test")
        enc_file = str(tmp_path / "enc.pfsh")
        rc, _ = _run_cli(
            ["encrypt", "--recipient", pub, "--output", enc_file, input_file]
        )
        assert rc == 0

    def test_decrypt_header_mac_mismatch_direct(self, tmp_path):
        pub1, priv1, _ = _make_pair(tmp_path, "pair1")
        pub2, priv2, _ = _make_pair(tmp_path, "pair2")
        enc_file = str(tmp_path / "enc.pfsh")
        rc, _ = _run_cli(
            ["encrypt", "--recipient", pub1, "--output", enc_file, "-"],
            b"secret",
        )
        assert rc == 0
        rc, _ = _run_cli(["decrypt", "--key", priv2, enc_file])
        assert rc == 2

    def test_encrypt_generic_exception_returns_1(self, tmp_path):
        pub, _, _ = _make_pair(tmp_path, "exc")

        def bad_encrypt(*args, **kwargs):
            raise RuntimeError("forced failure")

        with patch.object(cli, "encrypt", bad_encrypt):
            enc_file = str(tmp_path / "enc.pfsh")
            rc, _ = _run_cli(
                ["encrypt", "--recipient", pub, "--output", enc_file, "-"],
                b"test",
            )
            assert rc == 1