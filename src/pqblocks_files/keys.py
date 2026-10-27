"""Key storage I/O.

  save_public_key(keypair, path)              Bech32 text, HRP "pfsh1pq", mode 0444
  load_public_key(path)               -> Recipient
  save_private_key(keypair, path, passphrase) PEM-like text, scrypt + ChaCha20-Poly1305, mode 0600
  load_private_key(path, passphrase)  -> bytes
  keygen(classical_only=False)        -> KeyPair

Both file formats are versioned and carry an algorithm id; unknown versions or ids are refused.

Public key payload (before Bech32):   version(1) || alg(1) || key
Private key payload (before base64):  "PFSK" || version(1) || alg(1) || salt(16) || nonce(12) || ct || tag(16)
  alg 1 = ML-KEM-768 + X25519 hybrid (key = 1216 B public / 2432 B private)
  alg 2 = X25519 only                (key =   32 B public /   32 B private)
  Private key: key = scrypt(passphrase, salt, n=2**17, r=8, p=1) -> 32 B; AEAD = ChaCha20-Poly1305
  with the first 22 payload bytes (magic, version, alg, salt) as associated data.
  Format version 1 fixes these scrypt parameters; changing them needs a new version number.
"""

from __future__ import annotations

import base64
import binascii
import os
import stat

import bech32
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from pqblocks_files.kem import (
    HYBRID_PK_LEN,
    HYBRID_SK_LEN,
    MLKEM_PK_LEN,
    MLKEM_SK_LEN,
    X25519_LEN,
    hybrid_keygen as kem_hybrid_keygen,
    is_all_zero,
)
from pqblocks_files.pqtypes import KeyPair, Recipient

BECH32_HRP = "pfsh1pq"
PEM_HEADER = "-----BEGIN PFSH PRIVATE KEY-----\n"
PEM_FOOTER = "-----END PFSH PRIVATE KEY-----\n"
PRIVATE_KEY_MAGIC = b"PFSK"
PUBLIC_KEY_FORMAT_VERSION = 1
PRIVATE_KEY_FORMAT_VERSION = 1
ALG_HYBRID = 1
ALG_X25519_ONLY = 2
SALT_LEN = 16
NONCE_SIZE = 12
KEY_SIZE = 32
SCRYPT_N = 2 ** 17
SCRYPT_R = 8
SCRYPT_P = 1
_AAD_LEN = len(PRIVATE_KEY_MAGIC) + 2 + SALT_LEN       # magic, version, alg, salt
_PRIV_HEADER_LEN = _AAD_LEN + NONCE_SIZE
_TAG_LEN = 16
_MAX_KEY_FILE_BYTES = 1 << 20
_SECRET_LEN = {ALG_HYBRID: HYBRID_SK_LEN, ALG_X25519_ONLY: X25519_LEN}
_PUBLIC_LEN = {ALG_HYBRID: HYBRID_PK_LEN, ALG_X25519_ONLY: X25519_LEN}


def _check_passphrase(passphrase: bytes) -> None:
    if not isinstance(passphrase, (bytes, bytearray)):
        raise TypeError(f"passphrase must be bytes, got {type(passphrase).__name__}")
    if len(passphrase) == 0:
        raise ValueError("passphrase must not be empty")


def _derive_key_from_passphrase(passphrase: bytes, salt: bytes) -> bytes:
    """scrypt(passphrase, salt) -> 32-byte AEAD key (parameters fixed by key-file format v1)."""
    kdf = Scrypt(salt=salt, length=KEY_SIZE, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(bytes(passphrase))


def _write_new_file(path: str, data: bytes, mode: int) -> None:
    """Create path exclusively with the final mode from the first instant; never overwrite."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as fh:
            if hasattr(os, "fchmod"):
                os.fchmod(fh.fileno(), mode)    # exact mode even under an unusual umask
            fh.write(data)
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


def _read_capped(path: str) -> bytes:
    with open(path, "rb") as fh:
        data = fh.read(_MAX_KEY_FILE_BYTES + 1)
    if len(data) > _MAX_KEY_FILE_BYTES:
        raise ValueError("key file is too large")
    return data


def public_key_text(keypair: KeyPair) -> str:
    """Bech32 text form of the public key (what save_public_key writes)."""
    pk = keypair.public.hybrid_pk
    if len(pk) != HYBRID_PK_LEN:
        raise ValueError(f"hybrid_pk must be {HYBRID_PK_LEN}B, got {len(pk)}")
    if is_all_zero(pk[:MLKEM_PK_LEN]):
        payload = bytes([PUBLIC_KEY_FORMAT_VERSION, ALG_X25519_ONLY]) + pk[MLKEM_PK_LEN:]
    else:
        payload = bytes([PUBLIC_KEY_FORMAT_VERSION, ALG_HYBRID]) + pk
    groups = bech32.convertbits(payload, 8, 5, True)
    text = bech32.bech32_encode(BECH32_HRP, groups)
    if text is None:
        raise ValueError("failed to encode public key to Bech32")
    return text


def save_public_key(keypair: KeyPair, path: str) -> None:
    """Save the public key as Bech32 text (HRP 'pfsh1pq'), mode 0444. Never overwrites a file."""
    text = public_key_text(keypair)
    _write_new_file(path, text.encode("ascii"), stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)


def load_public_key(path: str) -> Recipient:
    """Load a public key file written by save_public_key. Raises ValueError on anything else."""
    try:
        text = _read_capped(path).decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("public key file is not ASCII text") from exc
    hrp, groups = bech32.bech32_decode(text)
    if groups is None:
        raise ValueError("invalid Bech32 string (bad checksum or characters)")
    if hrp != BECH32_HRP:
        raise ValueError(f"Invalid HRP: expected '{BECH32_HRP}', got '{hrp}'")
    raw = bech32.convertbits(groups, 5, 8, False)
    if raw is None:
        raise ValueError("invalid Bech32 payload padding")
    raw = bytes(raw)
    if len(raw) < 2:
        raise ValueError("public key payload too short")
    version, alg = raw[0], raw[1]
    if version != PUBLIC_KEY_FORMAT_VERSION:
        raise ValueError(f"unsupported public key format version {version}")
    if alg not in _PUBLIC_LEN:
        raise ValueError(f"unknown public key algorithm id {alg}")
    key = raw[2:]
    if len(key) != _PUBLIC_LEN[alg]:
        raise ValueError(f"decoded public key length {len(key)} != expected {_PUBLIC_LEN[alg]}")
    if alg == ALG_X25519_ONLY:
        key = bytes(MLKEM_PK_LEN) + key
    elif is_all_zero(key[:MLKEM_PK_LEN]):
        raise ValueError("hybrid public key has an all-zero ML-KEM part")
    return Recipient(hybrid_pk=key, label="")


def save_private_key(keypair: KeyPair, path: str, passphrase: bytes) -> None:
    """Save the private key encrypted under passphrase (scrypt + ChaCha20-Poly1305), mode 0600.

    A fresh random 16-byte salt and 12-byte nonce are drawn per file. Never overwrites a file.
    Raises ValueError for an empty passphrase.
    """
    _check_passphrase(passphrase)
    private = keypair.private
    if len(private) != HYBRID_SK_LEN:
        raise ValueError(f"private key must be {HYBRID_SK_LEN}B, got {len(private)}")
    if is_all_zero(private[:MLKEM_SK_LEN]):
        alg, secret = ALG_X25519_ONLY, private[MLKEM_SK_LEN:]
    else:
        alg, secret = ALG_HYBRID, private
    salt, nonce = os.urandom(SALT_LEN), os.urandom(NONCE_SIZE)
    aad = PRIVATE_KEY_MAGIC + bytes([PRIVATE_KEY_FORMAT_VERSION, alg]) + salt
    key = _derive_key_from_passphrase(passphrase, salt)
    sealed = ChaCha20Poly1305(key).encrypt(nonce, secret, aad)
    b64 = base64.b64encode(aad + nonce + sealed).decode("ascii")
    pem = PEM_HEADER + "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64)) + "\n" + PEM_FOOTER
    _write_new_file(path, pem.encode("ascii"), stat.S_IRUSR | stat.S_IWUSR)


def _parse_private_payload(path: str) -> bytes:
    try:
        text = _read_capped(path).decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("private key file is not ASCII text") from exc
    if not (text.startswith(PEM_HEADER) and text.endswith(PEM_FOOTER)):
        raise ValueError("unrecognised private key file format (not a PFSH PRIVATE KEY file)")
    body = "".join(text[len(PEM_HEADER):-len(PEM_FOOTER)].split())
    try:
        return base64.b64decode(body, validate=True)
    except binascii.Error as exc:
        raise ValueError(f"private key file is not valid base64: {exc}") from exc


def load_private_key(path: str, passphrase: bytes) -> bytes:
    """Decrypt a private key file written by save_private_key; returns the 2432-byte key.

    Structure (magic, version, algorithm id, exact length) is validated before the expensive KDF.
    Raises ValueError for a wrong passphrase, a corrupted file, or an unknown format.
    """
    _check_passphrase(passphrase)
    raw = _parse_private_payload(path)
    if len(raw) < _PRIV_HEADER_LEN + _TAG_LEN:
        raise ValueError(f"private key payload too short ({len(raw)} bytes)")
    if raw[:4] != PRIVATE_KEY_MAGIC:
        raise ValueError("bad private key magic")
    version, alg = raw[4], raw[5]
    if version != PRIVATE_KEY_FORMAT_VERSION:
        raise ValueError(f"unsupported private key format version {version}")
    if alg not in _SECRET_LEN:
        raise ValueError(f"unknown private key algorithm id {alg}")
    if len(raw) != _PRIV_HEADER_LEN + _SECRET_LEN[alg] + _TAG_LEN:
        raise ValueError(f"private key payload length {len(raw)} is wrong for algorithm id {alg}")
    aad, nonce, sealed = raw[:_AAD_LEN], raw[_AAD_LEN:_PRIV_HEADER_LEN], raw[_PRIV_HEADER_LEN:]
    key = _derive_key_from_passphrase(passphrase, aad[_AAD_LEN - SALT_LEN:])
    try:
        secret = ChaCha20Poly1305(key).decrypt(nonce, sealed, aad)
    except InvalidTag:
        raise ValueError("failed to decrypt private key (wrong passphrase or corrupted file)") from None
    if alg == ALG_X25519_ONLY:
        return bytes(MLKEM_SK_LEN) + secret
    if is_all_zero(secret[:MLKEM_SK_LEN]):
        raise ValueError("hybrid private key has an all-zero ML-KEM part")
    return secret


def keygen(classical_only: bool = False) -> KeyPair:
    """Generate a hybrid (ML-KEM-768 + X25519) keypair, or an X25519-only one.

    The X25519-only keypair keeps the fixed in-memory layout (zero-filled ML-KEM parts) but is
    stored on disk with its own algorithm id; it can only be used with classical_only=True.
    """
    if not classical_only:
        return kem_hybrid_keygen()
    x_sk = x25519.X25519PrivateKey.generate()
    return KeyPair(
        public=Recipient(
            hybrid_pk=bytes(MLKEM_PK_LEN) + x_sk.public_key().public_bytes_raw(), label=""
        ),
        private=bytes(MLKEM_SK_LEN) + x_sk.private_bytes_raw(),
    )
