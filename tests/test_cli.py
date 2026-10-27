"""CLI tests.

Contract under test:
  pqblocks-files keygen [--output pub.sec] [--output-sec priv.sec]
  pqblocks-files encrypt --recipient pub.sec [--recipient pub2.sec] [--output out.pfsh] [--classical] -
  pqblocks-files decrypt --key priv.sec [--output out.bin] in.pfsh

Exit codes:
  0 = Success
  1 = Bad input / malformed file / MAC failure
  2 = Key not found in header
  3 = ML-KEM key-check abort

Tests: encrypt + decrypt subprocess round-trip; keygen subcommand; error paths
"""

import os
import subprocess
import sys
import tempfile

import pytest

from tests.cli_pass import with_passphrase


def run_cli(args, cwd=None, input_data=None, env=None):
    """Run pqblocks-files CLI as subprocess. Returns (code, stdout, stderr)."""
    import os
    cmd = [sys.executable, "-m", "pqblocks_files.cli"] + with_passphrase(args)
    # Set PYTHONPATH to src so package is importable from subprocess
    src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
    env_path = os.environ.get("PYTHONPATH", "")
    new_env = dict(os.environ)
    new_env["PYTHONPATH"] = src_dir + (os.pathsep + env_path if env_path else "")
    if env:
        new_env.update(env)
    result = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        input=input_data,
        env=new_env,
    )
    return result.returncode, result.stdout, result.stderr


def keypair_from_cli(pub_path, priv_path, tmpdir):
    """Generate a keypair using the CLI keygen command."""
    code, out, err = run_cli(
        ["keygen", "--output", pub_path, "--output-sec", priv_path],
        cwd=tmpdir,
    )
    assert code == 0, f"keygen failed: {err.decode()}"
    return pub_path, priv_path


class TestKeygen:
    """Tests for the keygen subcommand."""

    def test_keygen_basic_subcommand_succeeds(self, tmp_path):
        pub = str(tmp_path / "pub.sec")
        priv = str(tmp_path / "priv.sec")
        code, out, err = run_cli(["keygen", "--output", pub, "--output-sec", priv], cwd=tmp_path)
        assert code == 0
        assert os.path.exists(pub)
        assert os.path.exists(priv)

    def test_keygen_output_files_valid(self, tmp_path):
        pub = str(tmp_path / "pub.sec")
        priv = str(tmp_path / "priv.sec")
        code, out, err = run_cli(["keygen", "--output", pub, "--output-sec", priv], cwd=tmp_path)
        assert code == 0
        # Pub file should be readable text (Bech32)
        with open(pub, "r", encoding="utf-8") as f:
            content = f.read().strip()
        assert content.startswith("pfsh1pq")

    def test_keygen_classical_only_mode(self, tmp_path):
        pub = str(tmp_path / "pub.sec")
        priv = str(tmp_path / "priv.sec")
        code, out, err = run_cli(
            ["keygen", "--classical", "--output", pub, "--output-sec", priv],
            cwd=tmp_path,
        )
        assert code == 0
        assert os.path.exists(pub)
        assert os.path.exists(priv)


class TestEncryptDecryptRoundTrip:
    """Tests for encrypt + decrypt subprocess round-trip."""

    def test_roundtrip_basic_plaintext(self, tmp_path):
        pub = str(tmp_path / "pub.sec")
        priv = str(tmp_path / "priv.sec")
        keypair_from_cli(pub, priv, tmp_path)

        plaintext = b"Hello, World!"
        enc_file = str(tmp_path / "enc.pfsh")
        dec_file = str(tmp_path / "dec.txt")

        # Encrypt
        code, out, err = run_cli(
            ["encrypt", "--recipient", pub, "--output", enc_file, "-"],
            cwd=tmp_path,
            input_data=plaintext,
        )
        assert code == 0, f"encrypt failed: {err.decode()}"
        assert os.path.exists(enc_file)

        # Decrypt
        code, out, err = run_cli(
            ["decrypt", "--key", priv, "--output", dec_file, enc_file],
            cwd=tmp_path,
        )
        assert code == 0, f"decrypt failed: {err.decode()}"
        with open(dec_file, "rb") as f:
            decrypted = f.read()
        assert decrypted == plaintext

    def test_roundtrip_empty_file(self, tmp_path):
        pub = str(tmp_path / "pub.sec")
        priv = str(tmp_path / "priv.sec")
        keypair_from_cli(pub, priv, tmp_path)

        plaintext = b""
        enc_file = str(tmp_path / "enc.pfsh")
        dec_file = str(tmp_path / "dec.txt")

        code, out, err = run_cli(
            ["encrypt", "--recipient", pub, "--output", enc_file, "-"],
            cwd=tmp_path,
            input_data=plaintext,
        )
        assert code == 0
        code, out, err = run_cli(
            ["decrypt", "--key", priv, "--output", dec_file, enc_file],
            cwd=tmp_path,
        )
        assert code == 0
        with open(dec_file, "rb") as f:
            assert f.read() == b""

    def test_roundtrip_multiple_recipients(self, tmp_path):
        pub1 = str(tmp_path / "pub1.sec")
        pub2 = str(tmp_path / "pub2.sec")
        priv1 = str(tmp_path / "priv1.sec")
        priv2 = str(tmp_path / "priv2.sec")
        keypair_from_cli(pub1, priv1, tmp_path)
        keypair_from_cli(pub2, priv2, tmp_path)

        plaintext = b"Multi-recipient payload test"
        enc_file = str(tmp_path / "enc.pfsh")
        dec_file1 = str(tmp_path / "dec1.txt")
        dec_file2 = str(tmp_path / "dec2.txt")

        code, out, err = run_cli(
            ["encrypt", "--recipient", pub1, "--recipient", pub2, "--output", enc_file, "-"],
            cwd=tmp_path,
            input_data=plaintext,
        )
        assert code == 0

        code, out, err = run_cli(
            ["decrypt", "--key", priv1, "--output", dec_file1, enc_file],
            cwd=tmp_path,
        )
        assert code == 0
        with open(dec_file1, "rb") as f:
            assert f.read() == plaintext

        code, out, err = run_cli(
            ["decrypt", "--key", priv2, "--output", dec_file2, enc_file],
            cwd=tmp_path,
        )
        assert code == 0
        with open(dec_file2, "rb") as f:
            assert f.read() == plaintext


class TestClassicalOnly:
    """Tests for --classical flag."""

    def test_classical_only_encrypt_decrypt_roundtrip(self, tmp_path):
        pub = str(tmp_path / "pub.sec")
        priv = str(tmp_path / "priv.sec")
        keypair_from_cli(pub, priv, tmp_path)

        plaintext = b"classical-only mode test"
        enc_file = str(tmp_path / "enc.pfsh")
        dec_file = str(tmp_path / "dec.txt")

        code, out, err = run_cli(
            ["encrypt", "--recipient", pub, "--output", enc_file, "--classical", "-"],
            cwd=tmp_path,
            input_data=plaintext,
        )
        assert code == 0

        code, out, err = run_cli(
            ["decrypt", "--key", priv, "--output", dec_file, enc_file],
            cwd=tmp_path,
        )
        assert code == 4          # classical-only file refused by default
        assert not os.path.exists(dec_file)

        code, out, err = run_cli(
            ["decrypt", "--key", priv, "--allow-classical", "--output", dec_file, enc_file],
            cwd=tmp_path,
        )
        assert code == 0
        with open(dec_file, "rb") as f:
            assert f.read() == plaintext


class TestExitCodes:
    """Tests for CLI exit codes."""

    def test_exit_code_0_success(self, tmp_path):
        pub = str(tmp_path / "pub.sec")
        priv = str(tmp_path / "priv.sec")
        keypair_from_cli(pub, priv, tmp_path)

        enc_file = str(tmp_path / "enc.pfsh")
        code, _, _ = run_cli(
            ["encrypt", "--recipient", pub, "--output", enc_file, "-"],
            cwd=tmp_path,
            input_data=b"test",
        )
        assert code == 0

        code, _, _ = run_cli(
            ["decrypt", "--key", priv, enc_file],
            cwd=tmp_path,
        )
        assert code == 0

    def test_exit_code_2_file_key_option_removed(self, tmp_path):
        pub = str(tmp_path / "pub.sec")
        keypair_from_cli(pub, str(tmp_path / "priv.sec"), tmp_path)

        code, out, err = run_cli(
            ["encrypt", "--recipient", pub, "--file-key", "invalid_hex", "-"],
            cwd=tmp_path,
            input_data=b"test",
        )
        assert code == 2          # argparse: --file-key no longer exists

    def test_exit_code_2_key_not_found_in_header(self, tmp_path):
        pub1 = str(tmp_path / "pub1.sec")
        priv1 = str(tmp_path / "priv1.sec")
        pub2 = str(tmp_path / "pub2.sec")
        priv2 = str(tmp_path / "priv2.sec")
        keypair_from_cli(pub1, priv1, tmp_path)
        keypair_from_cli(pub2, priv2, tmp_path)

        enc_file = str(tmp_path / "enc.pfsh")
        code, _, _ = run_cli(
            ["encrypt", "--recipient", pub1, "--output", enc_file, "-"],
            cwd=tmp_path,
            input_data=b"test",
        )
        assert code == 0

        code, _, _ = run_cli(
            ["decrypt", "--key", priv2, enc_file],
            cwd=tmp_path,
        )
        assert code == 2


class TestErrorPaths:
    """Tests for error conditions."""

    def test_decrypt_missing_key_file(self, tmp_path):
        enc_file = str(tmp_path / "enc.pfsh")
        code, _, _ = run_cli(
            ["decrypt", "--key", "/nonexistent/key.sec", enc_file],
            cwd=tmp_path,
        )
        assert code == 1

    def test_encrypt_missing_recipient(self, tmp_path):
        code, _, _ = run_cli(
            ["encrypt", "-"],
            cwd=tmp_path,
            input_data=b"test",
        )
        assert code == 2  # Required argument missing

    def test_decrypt_missing_input_file(self, tmp_path):
        pub = str(tmp_path / "pub.sec")
        priv = str(tmp_path / "priv.sec")
        keypair_from_cli(pub, priv, tmp_path)

        code, _, _ = run_cli(
            ["decrypt", "--key", priv, "/nonexistent.enc.pfsh"],
            cwd=tmp_path,
        )
        assert code == 1

    def test_invalid_pfsh_file(self, tmp_path):
        pub = str(tmp_path / "pub.sec")
        priv = str(tmp_path / "priv.sec")
        keypair_from_cli(pub, priv, tmp_path)

        bad_file = str(tmp_path / "bad.pfsh")
        with open(bad_file, "wb") as f:
            f.write(b"not a valid pfsh file")

        code, _, _ = run_cli(
            ["decrypt", "--key", priv, bad_file],
            cwd=tmp_path,
        )
        assert code == 1


class TestStdoutStdout:
    """Tests for stdout output behavior."""

    def test_encrypt_to_stdout_when_no_output(self, tmp_path):
        pub = str(tmp_path / "pub.sec")
        keypair_from_cli(pub, str(tmp_path / "priv.sec"), tmp_path)

        plaintext = b"stdout test"
        code, stdout, err = run_cli(
            ["encrypt", "--recipient", pub, "-"],
            cwd=tmp_path,
            input_data=plaintext,
        )
        assert code == 0
        assert not os.path.exists(str(tmp_path / "a.pfsh"))

    def test_decrypt_to_stdout_when_no_output(self, tmp_path):
        pub = str(tmp_path / "pub.sec")
        priv = str(tmp_path / "priv.sec")
        keypair_from_cli(pub, priv, tmp_path)

        plaintext = b"stdout decrypt test"
        enc_file = str(tmp_path / "enc.pfsh")

        code, _, _ = run_cli(
            ["encrypt", "--recipient", pub, "--output", enc_file, "-"],
            cwd=tmp_path,
            input_data=plaintext,
        )
        assert code == 0

        code, stdout, err = run_cli(
            ["decrypt", "--key", priv, enc_file],
            cwd=tmp_path,
        )
        assert code == 0
        assert stdout == plaintext


class TestHelpAndErrors:
    """Tests for help output and error handling."""

    def test_no_subcommand_returns_error(self, tmp_path):
        code, _, err = run_cli([], cwd=tmp_path)
        assert code == 1
        assert b"usage:" in err.lower() or b"pfshift-files" in err.lower()

    def test_keygen_help_works(self, tmp_path):
        code, stdout, err = run_cli(["keygen", "--help"], cwd=tmp_path)
        assert code == 0
        assert b"keygen" in stdout or b"keygen" in err

    def test_encrypt_help_works(self, tmp_path):
        code, stdout, err = run_cli(["encrypt", "--help"], cwd=tmp_path)
        assert code == 0

    def test_decrypt_help_works(self, tmp_path):
        code, stdout, err = run_cli(["decrypt", "--help"], cwd=tmp_path)
        assert code == 0