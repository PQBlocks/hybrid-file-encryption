"""Key storage I/O tests.

Contract under test :
  save_public_key(keypair, path)     -> None   (Bech32, HRP "pfsh1pq", 0444)
  load_public_key(path)              -> Recipient
  save_private_key(keypair, path, passphrase) -> None   (PEM-like, scrypt + ChaCha20-Poly1305, 0600)
  load_private_key(path, passphrase) -> bytes   (2432B)
  keygen(classical_only=False)        -> KeyPair
"""

import os
import stat

import pytest

from pqblocks_files.kem import hybrid_keygen
from pqblocks_files.keys import (
    load_private_key,
    load_public_key,
    save_private_key,
    save_public_key,
    keygen,
)
from pqblocks_files.pqtypes import KeyPair, Recipient


def _write_and_clean(path):
    """Context manager that removes path on exit."""
    def _cleanup():
        if os.path.exists(path):
            os.remove(path)
    return _cleanup


def test_keygen_returns_valid_keypair() -> None:
    kp = keygen()
    assert isinstance(kp, KeyPair)
    assert isinstance(kp.public, Recipient)
    assert len(kp.public.hybrid_pk) == 1216
    assert len(kp.private) == 2432


def test_keygen_classical_only_returns_valid_keypair() -> None:
    kp = keygen(classical_only=True)
    assert isinstance(kp, KeyPair)
    assert len(kp.public.hybrid_pk) == 1216
    assert len(kp.private) == 2432


def test_save_and_load_public_key_roundtrip(tmp_path) -> None:
    kp = hybrid_keygen()
    pub_path = str(tmp_path / "pub.sec")
    save_public_key(kp, pub_path)
    loaded = load_public_key(pub_path)
    assert loaded.hybrid_pk == kp.public.hybrid_pk
    assert loaded.label == kp.public.label


def test_public_key_file_has_0444_permissions(tmp_path) -> None:
    kp = hybrid_keygen()
    pub_path = str(tmp_path / "pub.sec")
    save_public_key(kp, pub_path)
    mode = os.stat(pub_path).st_mode
    assert stat.S_IMODE(mode) == 0o444


def test_save_and_load_private_key_roundtrip(tmp_path) -> None:
    kp = hybrid_keygen()
    priv_path = str(tmp_path / "priv.sec")
    passphrase = b"correct horse battery staple"
    save_private_key(kp, priv_path, passphrase)
    loaded_private = load_private_key(priv_path, passphrase)
    assert loaded_private == kp.private


def test_private_key_file_has_0600_permissions(tmp_path) -> None:
    kp = hybrid_keygen()
    priv_path = str(tmp_path / "priv.sec")
    passphrase = b"correct horse battery staple"
    save_private_key(kp, priv_path, passphrase)
    mode = os.stat(priv_path).st_mode
    assert stat.S_IMODE(mode) == 0o600


def test_load_private_key_wrong_passphrase_raises(tmp_path) -> None:
    kp = hybrid_keygen()
    priv_path = str(tmp_path / "priv.sec")
    save_private_key(kp, priv_path, b"right passphrase")
    with pytest.raises((ValueError, Exception)):
        load_private_key(priv_path, b"wrong passphrase")


def test_public_key_bech32_hrp_pfsh1pq(tmp_path) -> None:
    kp = hybrid_keygen()
    pub_path = str(tmp_path / "pub.sec")
    save_public_key(kp, pub_path)
    with open(pub_path, "r", encoding="utf-8") as fh:
        content = fh.read().strip()
    assert content.startswith("pfsh1pq")


def test_private_key_is_not_stored_in_plaintext(tmp_path) -> None:
    kp = hybrid_keygen()
    priv_path = str(tmp_path / "priv.sec")
    passphrase = b"correct horse battery staple"
    save_private_key(kp, priv_path, passphrase)
    with open(priv_path, "rb") as fh:
        raw = fh.read()
    assert kp.private not in raw


def test_classical_only_keygen_roundtrip_storage(tmp_path) -> None:
    kp = keygen(classical_only=True)
    pub_path = str(tmp_path / "pub.sec")
    priv_path = str(tmp_path / "priv.sec")
    passphrase = b"correct horse battery staple"
    save_public_key(kp, pub_path)
    save_private_key(kp, priv_path, passphrase)
    loaded_pub = load_public_key(pub_path)
    loaded_priv = load_private_key(priv_path, passphrase)
    assert loaded_pub.hybrid_pk == kp.public.hybrid_pk
    assert loaded_priv == kp.private


def test_two_keygens_produce_distinct_keys() -> None:
    kp1 = keygen()
    kp2 = keygen()
    assert kp1.public.hybrid_pk != kp2.public.hybrid_pk
    assert kp1.private != kp2.private
