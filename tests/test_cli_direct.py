"""CLI direct-invocation tests.

Run via `python -m pytest tests/test_cli_direct.py` (in-process) to
exercise the cli.py code paths without spawning subprocesses, in addition
to the subprocess round-trips in test_cli.py.
"""
import io
import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pqblocks_files import cli  # noqa: E402
from pqblocks_files.keys import keygen, save_public_key, save_private_key  # noqa: E402

from tests.cli_pass import TEST_PASSPHRASE as DEFAULT_PASSPHRASE, with_passphrase  # noqa: E402


class MockStdin:
    def __init__(self, raw_bytes):
        self.buffer = io.BytesIO(raw_bytes)
    def read(self, *args):
        return self.buffer.read(*args).decode("utf-8", errors="replace")

class MockStdout:
    def __init__(self):
        self.buffer = io.BytesIO()
    def write(self, s):
        if isinstance(s, bytes):
            return self.buffer.write(s)
        return self.buffer.write(s.encode("utf-8", errors="replace"))
    def flush(self):
        self.buffer.flush()

def _run_cli(argv, stdin_bytes=b""):
    """Call cli.main(argv) with stdin.buffer and stdout.buffer captured cleanly."""
    mock_in = MockStdin(stdin_bytes)
    mock_out = MockStdout()
    with patch("sys.stdin", mock_in), patch("sys.stdout", mock_out):
        rc = cli.main(with_passphrase(argv))
        out_bytes = mock_out.buffer.getvalue()
    return rc, out_bytes


def _make_pair(tmp_path, prefix="k"):
    kp = keygen()
    pub = str(tmp_path / f"{prefix}_pub.sec")
    priv = str(tmp_path / f"{prefix}_priv.sec")
    save_public_key(kp, pub)
    save_private_key(kp, priv, DEFAULT_PASSPHRASE)
    return pub, priv


class TestKeygenDirect:
    def test_keygen_main_success(self, tmp_path):
        pub = str(tmp_path / "pub.sec")
        priv = str(tmp_path / "priv.sec")
        rc, _ = _run_cli(["keygen", "--output", pub, "--output-sec", priv])
        assert rc == 0
        assert os.path.exists(pub)
        assert os.path.exists(priv)

    def test_keygen_stdin_default_public_print(self, tmp_path):
        priv = str(tmp_path / "priv_stdout.sec")
        rc, out = _run_cli(["keygen", "--output-sec", priv])
        assert rc == 0
        assert b"pfsh" in out
        assert os.path.exists(priv)


class TestEncryptDecryptDirect:
    def test_roundtrip_direct(self, tmp_path):
        pub, priv = _make_pair(tmp_path, "rt")
        enc_file = str(tmp_path / "enc.pfsh")
        plaintext = b"direct invocation test"
        rc, _ = _run_cli(["encrypt", "--recipient", pub, "--output", enc_file, "-"], plaintext)
        assert rc == 0

        dec_file = str(tmp_path / "dec.txt")
        rc, _ = _run_cli(["decrypt", "--key", priv, "--output", dec_file, enc_file])
        assert rc == 0
        with open(dec_file, "rb") as f:
            assert f.read() == plaintext

    def test_stdout_roundtrip_direct(self, tmp_path):
        pub, priv = _make_pair(tmp_path, "stdout")
        plaintext = b"stdout direct"
        rc, encrypted = _run_cli(["encrypt", "--recipient", pub, "-"], plaintext)
        assert rc == 0
        assert encrypted.startswith(b"pfsh-encryption.org/v1\n")

        enc_file = str(tmp_path / "enc_stdout.pfsh")
        with open(enc_file, "wb") as f:
            f.write(encrypted)
        
        dec_file = str(tmp_path / "dec_stdout.txt")
        rc, _ = _run_cli(["decrypt", "--key", priv, "--output", dec_file, enc_file])
        assert rc == 0
        with open(dec_file, "rb") as f:
            assert f.read() == plaintext

    def test_file_key_option_removed_direct(self, tmp_path):
        pub, _ = _make_pair(tmp_path, "bad_fk")
        with pytest.raises(SystemExit) as exc:
            _run_cli(["encrypt", "--recipient", pub, "--file-key", "zz", "-"], b"x")
        assert exc.value.code == 2

    def test_encrypt_missing_input_direct(self, tmp_path):
        pub, _ = _make_pair(tmp_path, "missing_in")
        rc, _ = _run_cli(["encrypt", "--recipient", pub, "nope.txt"], b"")
        assert rc != 0

    def test_decrypt_key_not_found_direct(self, tmp_path):
        pub2, priv2 = _make_pair(tmp_path, "pair2")
        rc, _ = _run_cli(["decrypt", "--key", "missing_priv.sec", pub2])
        assert rc != 0

    def test_decrypt_missing_key_direct(self, tmp_path):
        try:
            rc, _ = _run_cli(["decrypt", "some_file.pfsh"])
            assert rc != 0
        except SystemExit as exc:
            assert exc.code != 0

    def test_decrypt_invalid_pfsh_direct(self, tmp_path):
        _, priv = _make_pair(tmp_path, "inv")
        bad = str(tmp_path / "bad.pfsh")
        with open(bad, "wb") as f:
            f.write(b"NOT A PFSH FILE")
        rc, _ = _run_cli(["decrypt", "--key", priv, bad])
        assert rc != 0

    def test_truncated_file_direct(self, tmp_path):
        pub, priv = _make_pair(tmp_path, "trunc")
        enc = str(tmp_path / "enc_trunc.pfsh")
        rc, _ = _run_cli(["encrypt", "--recipient", pub, "--output", enc, "-"], b"abc")
        assert rc == 0
        with open(enc, "rb") as f:
            data = f.read()
        with open(enc, "wb") as f:
            f.write(data[:50])
        rc_dec, _ = _run_cli(["decrypt", "--key", priv, enc])
        assert rc_dec != 0

    def test_corrupted_ciphertext_direct(self, tmp_path):
        pub, priv = _make_pair(tmp_path, "corrupt")
        enc = str(tmp_path / "enc_corrupt.pfsh")
        rc, _ = _run_cli(["encrypt", "--recipient", pub, "--output", enc, "-"], b"payload to be corrupted")
        assert rc == 0
        with open(enc, "rb") as f:
            data = bytearray(f.read())
        if len(data) > 10:
            data[-5] ^= 0xFF
        with open(enc, "wb") as f:
            f.write(data)
        rc_dec, _ = _run_cli(["decrypt", "--key", priv, enc])
        assert rc_dec != 0


class TestMainContract:
    def test_no_subcommand_direct(self):
        rc, _ = _run_cli([])
        assert rc != 0

    def test_main_default_argv_none_uses_sys_argv(self):
        with patch.object(sys, "argv", ["pqblocks-files"]):
            rc = cli.main()
            assert rc != 0
