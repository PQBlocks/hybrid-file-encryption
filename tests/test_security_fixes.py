"""Regression tests for the crypto-integration review findings.

One group per finding. Each test fails on the pre-fix code and passes on the fixed code.
"""

import ast
import base64
import hmac
import importlib.util
import inspect
import os
import pathlib
import stat
import subprocess
import sys
import types

import pytest
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

import pqblocks_files
from pqblocks_files import cli, keys, kem
from pqblocks_files import encrypt as enc_mod
from pqblocks_files.chunker import _chunk
from pqblocks_files.encrypt import (
    _encrypt_with_file_key,
    decrypt,
    decrypt_with_mode,
    encrypt,
)
from pqblocks_files.header import _compute_mac, _encode_header
from pqblocks_files.keys import (
    keygen,
    load_private_key,
    load_public_key,
    save_private_key,
    save_public_key,
)
from pqblocks_files.pqtypes import (
    ClassicalOnlyRejected,
    HeaderMACMismatch,
    KeyPair,
    Recipient,
)

PASS = b"correct horse battery staple"
SRC_DIR = pathlib.Path(pqblocks_files.__file__).parent
OLD_DEFAULT_PASSPHRASE = b"pq" + b"shift-files-default-passphrase"  # the retired built-in default


def _run_cli(args, cwd, input_data=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC_DIR.parent) + os.pathsep + env.get("PYTHONPATH", "")
    r = subprocess.run(
        [sys.executable, "-m", "pqblocks_files.cli"] + args,
        cwd=cwd, capture_output=True, input=input_data, env=env,
    )
    return r.returncode, r.stdout, r.stderr


def _passfile(tmp_path, content=b"unique-Zx9-test-passphrase\n", name="pass.txt"):
    p = tmp_path / name
    p.write_bytes(content)
    return str(p)


def _payload(path):
    """Binary payload of a private key file (between the PEM-like lines)."""
    text = pathlib.Path(path).read_text()
    assert text.startswith(keys.PEM_HEADER) and text.endswith(keys.PEM_FOOTER)
    body = text[len(keys.PEM_HEADER):-len(keys.PEM_FOOTER)]
    return base64.b64decode("".join(body.split()))


def _write_payload(path, payload):
    b64 = base64.b64encode(payload).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    pathlib.Path(path).write_text(keys.PEM_HEADER + "\n".join(lines) + "\n" + keys.PEM_FOOTER)


# ---------------------------------------------------------------- (a) CLI passphrase

class TestCliPassphrase:
    def test_no_hardcoded_default_passphrase_in_source(self):
        for py in SRC_DIR.rglob("*.py"):
            text = py.read_text()
            assert "default-passphrase" not in text, py
            assert "pq" + "shift" not in text, py

    def test_cli_key_file_does_not_open_with_old_default_passphrase(self, tmp_path):
        pub, priv = str(tmp_path / "pub.sec"), str(tmp_path / "priv.sec")
        code, out, err = _run_cli(
            ["keygen", "--output", pub, "--output-sec", priv,
             "--passphrase-file", _passfile(tmp_path)], tmp_path)
        assert code == 0, err
        with pytest.raises(ValueError):
            load_private_key(priv, OLD_DEFAULT_PASSPHRASE)
        assert len(load_private_key(priv, b"unique-Zx9-test-passphrase")) == 2432

    def test_cli_keygen_never_prints_passphrase(self, tmp_path):
        secret = b"unique-Zx9-test-passphrase"
        code, out, err = _run_cli(
            ["keygen", "--output", str(tmp_path / "p.sec"), "--output-sec", str(tmp_path / "s.sec"),
             "--passphrase-file", _passfile(tmp_path)], tmp_path)
        assert code == 0
        assert secret not in out and secret not in err
        assert b"Passphrase:" not in err and b"default" not in err.lower()

    def test_cli_keygen_rejects_empty_passphrase_file(self, tmp_path):
        for content in (b"", b"\n", b"\r\n"):
            priv = tmp_path / "s.sec"
            code, out, err = _run_cli(
                ["keygen", "--output-sec", str(priv), "--passphrase-file",
                 _passfile(tmp_path, content, "empty.txt")], tmp_path)
            assert code == 1
            assert not priv.exists()
            assert b"empty" in err.lower()

    def test_cli_missing_passphrase_file_is_an_error(self, tmp_path):
        code, out, err = _run_cli(
            ["keygen", "--output-sec", str(tmp_path / "s.sec"),
             "--passphrase-file", str(tmp_path / "nope.txt")], tmp_path)
        assert code == 1
        assert not (tmp_path / "s.sec").exists()

    def test_cli_keygen_prompts_with_getpass_and_confirms(self, tmp_path, monkeypatch):
        answers = iter(["prompted-passphrase", "prompted-passphrase"])
        prompts = []
        monkeypatch.setattr(cli.getpass, "getpass", lambda p="": (prompts.append(p), next(answers))[1])
        priv = str(tmp_path / "s.sec")
        assert cli.main(["keygen", "--output-sec", priv, "--output", str(tmp_path / "p.sec")]) == 0
        assert len(prompts) == 2
        assert len(load_private_key(priv, b"prompted-passphrase")) == 2432

    def test_cli_keygen_confirmation_mismatch_rejected(self, tmp_path, monkeypatch):
        answers = iter(["one", "two"])
        monkeypatch.setattr(cli.getpass, "getpass", lambda p="": next(answers))
        priv = tmp_path / "s.sec"
        assert cli.main(["keygen", "--output-sec", str(priv)]) == 1
        assert not priv.exists()

    def test_cli_keygen_empty_prompt_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cli.getpass, "getpass", lambda p="": "")
        priv = tmp_path / "s.sec"
        assert cli.main(["keygen", "--output-sec", str(priv)]) == 1
        assert not priv.exists()

    def test_cli_decrypt_prompts_with_getpass(self, tmp_path, monkeypatch):
        pub, priv, pf = str(tmp_path / "p.sec"), str(tmp_path / "s.sec"), _passfile(tmp_path)
        assert _run_cli(["keygen", "--output", pub, "--output-sec", priv, "--passphrase-file", pf], tmp_path)[0] == 0
        encf = str(tmp_path / "e.pfsh")
        assert _run_cli(["encrypt", "-r", pub, "-o", encf, "-"], tmp_path, b"hi")[0] == 0
        monkeypatch.setattr(cli.getpass, "getpass", lambda p="": "unique-Zx9-test-passphrase")
        outf = tmp_path / "o.bin"
        assert cli.main(["decrypt", "-k", priv, "-o", str(outf), encf]) == 0
        assert outf.read_bytes() == b"hi"

    def test_cli_decrypt_wrong_passphrase_is_exit_2(self, tmp_path):
        pub, priv, pf = str(tmp_path / "p.sec"), str(tmp_path / "s.sec"), _passfile(tmp_path)
        _run_cli(["keygen", "--output", pub, "--output-sec", priv, "--passphrase-file", pf], tmp_path)
        encf = str(tmp_path / "e.pfsh")
        _run_cli(["encrypt", "-r", pub, "-o", encf, "-"], tmp_path, b"hi")
        wrong = _passfile(tmp_path, b"wrong", "wrong.txt")
        code, out, err = _run_cli(["decrypt", "-k", priv, "--passphrase-file", wrong, encf], tmp_path)
        assert code == 2
        assert b"wrong" not in err.replace(b"wrong passphrase", b"")

    def test_library_rejects_empty_passphrase(self, tmp_path):
        kp = keygen()
        with pytest.raises(ValueError, match="empty"):
            save_private_key(kp, str(tmp_path / "s.sec"), b"")
        assert not (tmp_path / "s.sec").exists()
        save_private_key(kp, str(tmp_path / "t.sec"), PASS)
        with pytest.raises(ValueError, match="empty"):
            load_private_key(str(tmp_path / "t.sec"), b"")

    def test_library_rejects_non_bytes_passphrase(self, tmp_path):
        with pytest.raises(TypeError):
            save_private_key(keygen(), str(tmp_path / "s.sec"), "a str")


# ---------------------------------------------------------------- (b) KDF salt + versioned key file

class TestPrivateKeyFileFormat:
    def test_scrypt_parameters(self):
        assert (keys.SCRYPT_N, keys.SCRYPT_R, keys.SCRYPT_P) == (2 ** 17, 8, 1)
        assert keys.SALT_LEN == 16

    def test_layout_and_independent_decryption(self, tmp_path):
        """Re-implement the documented layout in the test and decrypt without keys.py."""
        kp = keygen()
        path = str(tmp_path / "s.sec")
        save_private_key(kp, path, PASS)
        raw = _payload(path)
        assert raw[:4] == b"PFSK"
        assert raw[4] == 1          # format version
        assert raw[5] == 1          # algorithm id: hybrid
        salt, nonce, ct = raw[6:22], raw[22:34], raw[34:]
        assert len(ct) == 2432 + 16
        key = Scrypt(salt=salt, length=32, n=2 ** 17, r=8, p=1).derive(PASS)
        assert ChaCha20Poly1305(key).decrypt(nonce, ct, raw[:22]) == kp.private

    def test_roundtrip_with_loaded_key_decrypts_a_file(self, tmp_path):
        kp = keygen()
        path = str(tmp_path / "s.sec")
        save_private_key(kp, path, PASS)
        loaded = load_private_key(path, PASS)
        assert loaded == kp.private
        blob = encrypt(b"through a stored key", [kp.public])
        assert decrypt(blob, KeyPair(public=kp.public, private=loaded)) == b"through a stored key"

    def test_salt_is_random_per_file(self, tmp_path):
        kp = keygen()
        a, b = str(tmp_path / "a.sec"), str(tmp_path / "b.sec")
        save_private_key(kp, a, PASS)
        save_private_key(kp, b, PASS)
        ra, rb = _payload(a), _payload(b)
        assert ra[6:22] != rb[6:22]
        assert ra[6:22] != bytes(16)
        assert ra != rb

    def test_unknown_version_rejected(self, tmp_path):
        path = str(tmp_path / "s.sec")
        save_private_key(keygen(), path, PASS)
        raw = bytearray(_payload(path))
        raw[4] = 2
        _write_payload(path, bytes(raw))
        with pytest.raises(ValueError, match="version"):
            load_private_key(path, PASS)

    def test_unknown_algorithm_id_rejected(self, tmp_path):
        path = str(tmp_path / "s.sec")
        save_private_key(keygen(), path, PASS)
        raw = bytearray(_payload(path))
        raw[5] = 9
        _write_payload(path, bytes(raw))
        with pytest.raises(ValueError, match="algorithm"):
            load_private_key(path, PASS)

    def test_bad_magic_rejected(self, tmp_path):
        path = str(tmp_path / "s.sec")
        save_private_key(keygen(), path, PASS)
        raw = bytearray(_payload(path))
        raw[0] ^= 1
        _write_payload(path, bytes(raw))
        with pytest.raises(ValueError, match="magic"):
            load_private_key(path, PASS)

    @pytest.mark.parametrize("offset", [5, 6, 21, 22, 40])
    def test_header_and_body_bit_flips_rejected(self, tmp_path, offset):
        """Algorithm id and salt are bound as AAD; nonce and ciphertext by the tag."""
        path = str(tmp_path / "s.sec")
        save_private_key(keygen(), path, PASS)
        raw = bytearray(_payload(path))
        raw[offset] ^= 0x01
        _write_payload(path, bytes(raw))
        with pytest.raises(ValueError):
            load_private_key(path, PASS)

    def test_algorithm_id_swap_to_classical_rejected(self, tmp_path):
        path = str(tmp_path / "s.sec")
        save_private_key(keygen(), path, PASS)
        raw = bytearray(_payload(path))
        raw[5] = 2
        _write_payload(path, bytes(raw))
        with pytest.raises(ValueError):
            load_private_key(path, PASS)

    @pytest.mark.parametrize("cut", [0, 3, 10, 33, 34, 50])
    def test_truncated_payload_rejected(self, tmp_path, cut):
        path = str(tmp_path / "s.sec")
        save_private_key(keygen(), path, PASS)
        _write_payload(path, _payload(path)[:cut])
        with pytest.raises(ValueError):
            load_private_key(path, PASS)

    def test_extra_trailing_bytes_rejected(self, tmp_path):
        path = str(tmp_path / "s.sec")
        save_private_key(keygen(), path, PASS)
        _write_payload(path, _payload(path) + b"\x00")
        with pytest.raises(ValueError):
            load_private_key(path, PASS)

    def test_old_unversioned_format_rejected(self, tmp_path):
        """A file in the retired layout (old PEM label) is refused loudly, not guessed at."""
        path = tmp_path / "old.sec"
        path.write_text("-----BEGIN PFS1PRIVATE KEY-----\nAAAA\n-----END PFS1PRIVATE KEY-----\n")
        with pytest.raises(ValueError, match="format"):
            load_private_key(str(path), PASS)

    def test_non_base64_rejected(self, tmp_path):
        path = tmp_path / "bad.sec"
        path.write_text(keys.PEM_HEADER + "!!!not base64!!!\n" + keys.PEM_FOOTER)
        with pytest.raises(ValueError):
            load_private_key(str(path), PASS)

    def test_oversized_file_rejected(self, tmp_path):
        path = tmp_path / "big.sec"
        path.write_text(keys.PEM_HEADER + "A" * (1 << 21) + keys.PEM_FOOTER)
        with pytest.raises(ValueError, match="large"):
            load_private_key(str(path), PASS)


# ---------------------------------------------------------------- (c) no caller-supplied file_key

class TestNoCallerFileKey:
    def test_encrypt_signature_has_no_file_key(self):
        assert "file_key" not in inspect.signature(encrypt).parameters

    def test_encrypt_rejects_file_key_keyword(self):
        kp = keygen()
        with pytest.raises(TypeError):
            encrypt(b"x", [kp.public], file_key=bytes(16))

    def test_every_encrypt_uses_a_fresh_file_key(self):
        """Two encryptions of the same plaintext share no keystream: bodies differ."""
        from pqblocks_files.encrypt import parse_pfsh
        kp = keygen()
        pt = b"A" * 100
        _, b1, _ = parse_pfsh(encrypt(pt, [kp.public]))
        _, b2, _ = parse_pfsh(encrypt(pt, [kp.public]))
        assert b1 != b2

    def test_keystream_reuse_poc_no_longer_reachable(self):
        """Review PoC: two files under one file_key leak ct1^ct2 == p1^p2. Through the public
        API the file key is random, so the XOR of two bodies is not the XOR of the plaintexts."""
        from pqblocks_files.encrypt import parse_pfsh
        kp = keygen()
        p1, p2 = b"attack at dawn!!" * 4, b"retreat at nine!" * 4
        _, b1, _ = parse_pfsh(encrypt(p1, [kp.public]))
        _, b2, _ = parse_pfsh(encrypt(p2, [kp.public]))
        n = len(p1)
        x = bytes(a ^ b for a, b in zip(b1[12:12 + n], b2[12:12 + n]))
        assert x != bytes(a ^ b for a, b in zip(p1, p2))

    def test_private_hook_still_validates_length(self):
        kp = keygen()
        with pytest.raises(ValueError, match="file_key must be 16"):
            _encrypt_with_file_key(b"d", [kp.public], b"\x00" * 32)

    def test_cli_rejects_file_key_option(self, tmp_path):
        pub = str(tmp_path / "p.sec")
        _run_cli(["keygen", "--output", pub], tmp_path)
        code, out, err = _run_cli(["encrypt", "-r", pub, "--file-key", "00" * 16, "-"], tmp_path, b"x")
        assert code == 2
        assert b"--file-key" in err

    def test_reference_oracle_is_not_shipped_in_the_package(self):
        assert importlib.util.find_spec("pqblocks_files.oracles") is None
        assert not (SRC_DIR / "oracles").exists()


# ---------------------------------------------------------------- (d) require_pq default

class TestRequirePq:
    def test_default_rejects_classical_only_file(self):
        kp = keygen()
        blob = encrypt(b"secret", [kp.public], classical_only=True)
        with pytest.raises(ClassicalOnlyRejected):
            decrypt(blob, kp)

    def test_classical_rejection_is_not_header_mismatch(self):
        assert not issubclass(ClassicalOnlyRejected, HeaderMACMismatch)

    def test_explicit_opt_in_decrypts_and_reports_classical(self):
        kp = keygen()
        blob = encrypt(b"secret", [kp.public], classical_only=True)
        assert decrypt(blob, kp, require_pq=False) == b"secret"
        res = decrypt_with_mode(blob, kp, require_pq=False)
        assert res.plaintext == b"secret"
        assert res.mode == enc_mod.MODE_CLASSICAL

    def test_hybrid_file_reports_hybrid_mode(self):
        kp = keygen()
        blob = encrypt(b"secret", [kp.public])
        res = decrypt_with_mode(blob, kp)
        assert (res.plaintext, res.mode) == (b"secret", enc_mod.MODE_HYBRID)
        assert decrypt(blob, kp) == b"secret"
        assert decrypt(blob, kp, require_pq=False) == b"secret"

    def test_decrypt_result_repr_hides_plaintext(self):
        kp = keygen()
        res = decrypt_with_mode(encrypt(b"top-secret-bytes", [kp.public]), kp)
        assert "top-secret-bytes" not in repr(res)

    def test_default_signature_is_require_pq_true(self):
        assert inspect.signature(decrypt).parameters["require_pq"].default is True
        assert inspect.signature(decrypt_with_mode).parameters["require_pq"].default is True

    def test_require_pq_must_be_bool(self):
        kp = keygen()
        blob = encrypt(b"x", [kp.public])
        with pytest.raises(TypeError):
            decrypt(blob, kp, require_pq="no")

    def test_mixed_header_hybrid_stanza_still_decrypts_under_policy(self):
        """A file that carries one hybrid and one classical stanza is readable by the hybrid
        recipient without opting in; the classical stanza is simply never used."""
        kp_h, kp_c = keygen(), keygen()
        fk = os.urandom(16)
        h_hybrid = _encode_header([kp_h.public], fk)
        h_classic = _encode_header([kp_c.public], fk, classical_only=True)
        stanzas = h_hybrid.split(b"=== ")[0] + h_classic.split(b"pfsh-encryption.org/v1\n")[1].split(b"=== ")[0]
        body = stanzas
        mac = base64.b64encode(_compute_mac(fk, body))
        blob = body + b"=== " + mac + b"\n" + b"".join(n + c for n, c in _chunk(b"mixed", fk)) + enc_mod.END_MARKER
        assert decrypt(blob, kp_h) == b"mixed"
        with pytest.raises(ClassicalOnlyRejected):
            decrypt(blob, kp_c)
        assert decrypt(blob, kp_c, require_pq=False) == b"mixed"

    def test_other_recipients_classical_file_is_plain_key_not_found(self):
        """Policy rejection is only reported to someone who could have read the file."""
        blob = encrypt(b"x", [keygen().public], classical_only=True)
        with pytest.raises(HeaderMACMismatch):
            decrypt(blob, keygen())

    def test_cli_default_rejects_classical_file_exit_4(self, tmp_path):
        pub, priv, pf = str(tmp_path / "p.sec"), str(tmp_path / "s.sec"), _passfile(tmp_path)
        _run_cli(["keygen", "--output", pub, "--output-sec", priv, "--passphrase-file", pf], tmp_path)
        encf = str(tmp_path / "e.pfsh")
        assert _run_cli(["encrypt", "-r", pub, "--classical", "-o", encf, "-"], tmp_path, b"cl")[0] == 0
        code, out, err = _run_cli(["decrypt", "-k", priv, "--passphrase-file", pf, encf], tmp_path)
        assert code == 4
        assert out == b"" and b"--allow-classical" in err
        code, out, err = _run_cli(["decrypt", "-k", priv, "--passphrase-file", pf, "--allow-classical", encf], tmp_path)
        assert code == 0 and out == b"cl"


# ---------------------------------------------------------------- (e) algorithm id + zero ML-KEM key

class TestAlgorithmIdAndZeroKey:
    def test_hybrid_encap_rejects_all_zero_mlkem_public_key(self):
        classical = keygen(classical_only=True)
        with pytest.raises(ValueError, match="all-zero"):
            kem.hybrid_encap(classical.public.hybrid_pk)

    def test_encrypt_to_classical_key_without_opt_in_is_rejected(self):
        classical = keygen(classical_only=True)
        with pytest.raises(ValueError, match="all-zero"):
            encrypt(b"x", [classical.public])

    def test_classical_key_round_trip_with_explicit_opt_in(self):
        classical = keygen(classical_only=True)
        blob = encrypt(b"x", [classical.public], classical_only=True)
        assert decrypt(blob, classical, require_pq=False) == b"x"
        with pytest.raises(ClassicalOnlyRejected):
            decrypt(blob, classical)

    def test_public_key_file_carries_version_and_algorithm_id(self, tmp_path):
        import bech32
        path = str(tmp_path / "p.sec")
        save_public_key(keygen(), path)
        hrp, data = bech32.bech32_decode(pathlib.Path(path).read_text().strip())
        raw = bytes(bech32.convertbits(data, 5, 8, False))
        assert hrp == "pfsh1pq"
        assert raw[0] == 1 and raw[1] == 1
        assert len(raw) == 2 + 1216

    def test_classical_public_key_file_stores_only_the_x25519_key(self, tmp_path):
        import bech32
        kp = keygen(classical_only=True)
        path = str(tmp_path / "p.sec")
        save_public_key(kp, path)
        hrp, data = bech32.bech32_decode(pathlib.Path(path).read_text().strip())
        raw = bytes(bech32.convertbits(data, 5, 8, False))
        assert raw[:2] == bytes([1, 2]) and len(raw) == 2 + 32
        assert load_public_key(path).hybrid_pk == kp.public.hybrid_pk

    def test_classical_private_key_file_roundtrip_and_algorithm_id(self, tmp_path):
        kp = keygen(classical_only=True)
        path = str(tmp_path / "s.sec")
        save_private_key(kp, path, PASS)
        assert _payload(path)[5] == 2
        assert load_private_key(path, PASS) == kp.private

    def test_hybrid_labelled_key_with_zero_mlkem_part_refused_on_save(self, tmp_path):
        bad = KeyPair(public=Recipient(hybrid_pk=bytes(1184) + bytes(32)), private=bytes(2400) + bytes(32))
        # all-zero ML-KEM part means "classical": saved as such, never as a hybrid key
        path = str(tmp_path / "s.sec")
        save_private_key(bad, path, PASS)
        assert _payload(path)[5] == 2

    def test_inconsistent_public_key_algorithm_rejected(self, tmp_path):
        import bech32
        path = tmp_path / "p.sec"
        raw = bytes([1, 1]) + bytes(1184) + bytes(32)   # claims hybrid but ML-KEM part is zero
        five = bech32.convertbits(raw, 8, 5, True)
        path.write_text(bech32.bech32_encode("pfsh1pq", five))
        with pytest.raises(ValueError, match="all-zero"):
            load_public_key(str(path))

    def test_unknown_public_key_algorithm_and_version_rejected(self, tmp_path):
        import bech32
        for head, match in ((bytes([1, 9]), "algorithm"), (bytes([2, 1]), "version")):
            path = tmp_path / "p.sec"
            path.write_text(bech32.bech32_encode("pfsh1pq", bech32.convertbits(head + bytes(1216), 8, 5, True)))
            with pytest.raises(ValueError, match=match):
                load_public_key(str(path))
            path.unlink()

    def test_wrong_hrp_rejected(self, tmp_path):
        import bech32
        path = tmp_path / "p.sec"
        path.write_text(bech32.bech32_encode("other", bech32.convertbits(bytes([1, 1]) + bytes(1216), 8, 5, True)))
        with pytest.raises(ValueError, match="HRP"):
            load_public_key(str(path))


# ---------------------------------------------------------------- (f) liboqs binding

class TestLiboqsBinding:
    def test_supported_versions_accepted(self):
        for v in (b"0.15.0", b"0.15.2", b"0.16.0"):
            kem._check_oqs_version(v)

    @pytest.mark.parametrize("v", [b"0.14.0", b"0.12.0", b"0.17.0", b"1.0.0", b"garbage", b"", None])
    def test_unsupported_versions_rejected(self, v):
        with pytest.raises(RuntimeError, match="liboqs"):
            kem._check_oqs_version(v)

    def test_loaded_library_passes_version_check(self):
        kem._check_oqs_version(kem._lib.OQS_version())

    def test_kem_size_mismatch_raises_runtime_error(self):
        good = types.SimpleNamespace(length_public_key=1184, length_secret_key=2400,
                                     length_ciphertext=1088, length_shared_secret=32)
        kem._verify_kem_struct(good)
        for field in vars(good):
            bad = types.SimpleNamespace(**vars(good))
            setattr(bad, field, getattr(bad, field) + 1)
            with pytest.raises(RuntimeError, match=field):
                kem._verify_kem_struct(bad)

    def test_no_assert_statements_in_package(self):
        for py in SRC_DIR.rglob("*.py"):
            tree = ast.parse(py.read_text())
            assert not [n for n in ast.walk(tree) if isinstance(n, ast.Assert)], py

    def _python_O(self, code):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(SRC_DIR.parent) + os.pathsep + env.get("PYTHONPATH", "")
        return subprocess.run([sys.executable, "-O", "-c", code], capture_output=True, env=env, text=True)

    def test_checks_still_enforced_under_python_O(self):
        code = (
            "import types\n"
            "from pqblocks_files import kem\n"
            "bad = types.SimpleNamespace(length_public_key=1, length_secret_key=2400,"
            " length_ciphertext=1088, length_shared_secret=32)\n"
            "try:\n"
            "    kem._verify_kem_struct(bad)\n"
            "except RuntimeError:\n"
            "    print('raised')\n"
        )
        r = self._python_O(code)
        assert r.stdout.strip() == "raised", r.stderr

    def test_round_trip_under_python_O(self):
        code = (
            "from pqblocks_files.keys import keygen\n"
            "from pqblocks_files.encrypt import encrypt, decrypt\n"
            "kp = keygen()\n"
            "print(decrypt(encrypt(b'abc', [kp.public]), kp))\n"
        )
        r = self._python_O(code)
        assert r.stdout.strip() == "b'abc'", r.stderr


# ---------------------------------------------------------------- MEDIUM / LOW items

class TestHardening:
    def test_keypair_repr_hides_private_key(self):
        kp = keygen()
        text = repr(kp)
        assert kp.private.hex() not in text
        assert repr(kp.private) not in text
        assert str(kp.private[:16]) not in text
        assert "private" not in text

    def test_unchunk_is_not_public(self):
        from pqblocks_files import chunker
        assert not hasattr(chunker, "unchunk")
        assert hasattr(chunker, "_unchunk")

    def test_low_order_c_x25519_in_other_stanza_does_not_abort_decrypt(self):
        """Review LOW: a stanza whose C_x25519 is a low-order point must be skipped, not raise."""
        kp_other, kp_me = keygen(), keygen()
        fk = os.urandom(16)
        header = _encode_header([kp_other.public, kp_me.public], fk)
        lines = header.split(b"\n")
        first_arg = lines[1].split(b" ")
        first_arg[2] = base64.b64encode(bytes(32))        # low-order point (u = 0)
        lines[1] = b" ".join(first_arg)
        body = b"\n".join(lines[:-2]) + b"\n"
        mac = base64.b64encode(_compute_mac(fk, body))
        blob = body + b"=== " + mac + b"\n" + b"".join(n + c for n, c in _chunk(b"payload", fk)) + enc_mod.END_MARKER
        assert decrypt(blob, kp_me) == b"payload"
        with pytest.raises(HeaderMACMismatch):
            decrypt(blob, keygen())

    def test_low_order_point_with_classical_stanza_skipped(self):
        kp = keygen()
        fk = os.urandom(16)
        header = _encode_header([kp.public], fk, classical_only=True)
        lines = header.split(b"\n")
        arg = lines[1].split(b" ")
        arg[2] = base64.b64encode(bytes(32))
        lines[1] = b" ".join(arg)
        body = b"\n".join(lines[:-2]) + b"\n"
        mac = base64.b64encode(_compute_mac(fk, body))
        blob = body + b"=== " + mac + b"\n" + b"".join(n + c for n, c in _chunk(b"p", fk)) + enc_mod.END_MARKER
        with pytest.raises(HeaderMACMismatch):
            decrypt(blob, kp, require_pq=False)

    def test_private_key_created_atomically_with_0600(self, tmp_path, monkeypatch):
        calls = []
        real_open = os.open

        def spy(path, flags, mode=0o777, **kw):
            calls.append((str(path), flags, mode))
            return real_open(path, flags, mode, **kw)

        monkeypatch.setattr(os, "open", spy)
        old = os.umask(0)
        try:
            path = str(tmp_path / "s.sec")
            save_private_key(keygen(), path, PASS)
        finally:
            os.umask(old)
        mine = [c for c in calls if c[0] == path]
        assert mine and mine[0][1] & os.O_EXCL and mine[0][1] & os.O_CREAT
        assert mine[0][2] == 0o600
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    def test_save_private_key_never_overwrites(self, tmp_path):
        path = tmp_path / "s.sec"
        path.write_text("precious")
        with pytest.raises(FileExistsError):
            save_private_key(keygen(), str(path), PASS)
        assert path.read_text() == "precious"

    def test_save_public_key_never_overwrites_and_is_0444(self, tmp_path):
        path = tmp_path / "p.sec"
        kp = keygen()
        save_public_key(kp, str(path))
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o444
        with pytest.raises(FileExistsError):
            save_public_key(kp, str(path))

    def test_public_key_exact_decoded_length_required(self, tmp_path):
        import bech32
        path = tmp_path / "p.sec"
        for extra in (b"\x00", b"\x00" * 7, b"\xff" * 40):
            raw = bytes([1, 1]) + os.urandom(1216) + extra
            path.write_text(bech32.bech32_encode("pfsh1pq", bech32.convertbits(raw, 8, 5, True)))
            with pytest.raises(ValueError, match="length"):
                load_public_key(str(path))
            path.unlink()
        raw = bytes([1, 1]) + os.urandom(1215)
        path.write_text(bech32.bech32_encode("pfsh1pq", bech32.convertbits(raw, 8, 5, True)))
        with pytest.raises(ValueError, match="length"):
            load_public_key(str(path))

    def test_public_key_nonzero_padding_bits_rejected(self, tmp_path):
        import bech32
        path = tmp_path / "p.sec"
        five = bech32.convertbits(bytes([1, 1]) + os.urandom(1216), 8, 5, True)
        five[-1] |= 1                       # set a padding bit (1218 bytes = 9744 bits, 1 pad bit)
        path.write_text(bech32.bech32_encode("pfsh1pq", five))
        with pytest.raises(ValueError):
            load_public_key(str(path))

    def test_docstrings_do_not_say_32_bit_or_kyber(self):
        for py in SRC_DIR.rglob("*.py"):
            text = py.read_text().lower()
            assert "32-bit key" not in text, py
            assert "kyber" not in text, py


class TestNoPublicFileKeyReuseHelpers:
    """Helpers that take a caller-chosen file key / ephemeral key are private."""

    def test_unsafe_helpers_not_public(self):
        from pqblocks_files import chunker, header

        assert not hasattr(chunker, "chunk")
        assert not hasattr(header, "encode_header")
        for fn in (kem.hybrid_encap, kem.classical_only_encap):
            assert "eph_x25519_sk" not in inspect.signature(fn).parameters
            assert "_eph_x25519_sk" in inspect.signature(fn).parameters

    def test_classical_key_holder_gets_key_not_found_on_hybrid_stanza(self):
        hybrid = keygen()
        classical = keygen(classical_only=True)
        blob = encrypt(b"x", [hybrid.public])
        with pytest.raises(HeaderMACMismatch):
            decrypt(blob, classical, require_pq=False)
