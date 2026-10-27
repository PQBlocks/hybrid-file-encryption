"""Hybrid KEM core: ML-KEM-768 (liboqs) plus X25519 (pyca/cryptography).

Simple combiner, NOT full HPKE: K_hybrid =
HKDF-SHA256(K_mlkem || K_x25519, salt=b"", info=b"pfsh-hybrid").
The combiner does not bind the X25519 ciphertext or the public keys (see SECURITY_NOTES.md).

Backends are audited libraries only: liboqs (ML-KEM-768) via ctypes and
pyca/cryptography (X25519, HKDF-SHA256). No hand-rolled primitives.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import hmac
import os
import re
from typing import Optional, Tuple

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pqblocks_files.pqtypes import KeyPair, LowOrderX25519, MLKEMKeyCheckFailed, Recipient

MLKEM_PK_LEN = 1184
MLKEM_SK_LEN = 2400
MLKEM_CT_LEN = 1088
MLKEM_SS_LEN = 32
X25519_LEN = 32
HYBRID_PK_LEN = MLKEM_PK_LEN + X25519_LEN
HYBRID_SK_LEN = MLKEM_SK_LEN + X25519_LEN
C_HYBRID_LEN = MLKEM_CT_LEN + X25519_LEN
K_HYBRID_LEN = 32
_HKDF_INFO = b"pfsh-hybrid"
_MLKEM_ALG = b"ML-KEM-768"
_OQS_SUCCESS = 0

# liboqs releases this binding has been written and tested against (major, minor). The soname
# alone is not enough (0.15 and 0.16 share liboqs.so.9), so the version string is checked at import.
SUPPORTED_LIBOQS = ((0, 15), (0, 16))


class _OqsKem(ctypes.Structure):
    _fields_ = [
        ("method_name", ctypes.c_char_p),
        ("alg_version", ctypes.c_char_p),
        ("claimed_nist_level", ctypes.c_uint8),
        ("ind_cca", ctypes.c_bool),
        ("length_public_key", ctypes.c_size_t),
        ("length_secret_key", ctypes.c_size_t),
        ("length_ciphertext", ctypes.c_size_t),
        ("length_shared_secret", ctypes.c_size_t),
    ]


def _load_liboqs() -> ctypes.CDLL:
    """Load liboqs. OQS_LIB_PATH, when set, is the only candidate (no silent fallback)."""
    explicit = os.environ.get("OQS_LIB_PATH")
    if explicit:
        candidates = [explicit]
    else:
        candidates = [c for c in (ctypes.util.find_library("oqs"), "liboqs.so.9") if c]
    last_error: Exception | None = None
    for path in candidates:
        try:
            return ctypes.CDLL(path)
        except OSError as exc:
            last_error = exc
    raise RuntimeError(f"liboqs not available: {last_error}")


def _check_oqs_version(raw: Optional[bytes]) -> Tuple[int, int, int]:
    """Parse OQS_version() and require a supported major.minor. Raises RuntimeError otherwise."""
    text = raw.decode("ascii", "replace") if raw else ""
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", text)
    if m is None:
        raise RuntimeError(f"liboqs: cannot parse version {text!r}")
    version = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    if version[:2] not in SUPPORTED_LIBOQS:
        supported = ", ".join("%d.%d.x" % v for v in SUPPORTED_LIBOQS)
        raise RuntimeError(f"liboqs {text} is not supported (need {supported})")
    return version


def _verify_kem_struct(kem_struct) -> None:
    """Check liboqs' ML-KEM-768 sizes against the constants used for buffers. Raises RuntimeError."""
    for field, expected in (
        ("length_public_key", MLKEM_PK_LEN),
        ("length_secret_key", MLKEM_SK_LEN),
        ("length_ciphertext", MLKEM_CT_LEN),
        ("length_shared_secret", MLKEM_SS_LEN),
    ):
        got = getattr(kem_struct, field)
        if got != expected:
            raise RuntimeError(f"liboqs ML-KEM-768 {field} is {got}, expected {expected}")


_lib = _load_liboqs()
_lib.OQS_version.argtypes = []
_lib.OQS_version.restype = ctypes.c_char_p
_check_oqs_version(_lib.OQS_version())
_lib.OQS_KEM_new.argtypes = [ctypes.c_char_p]
_lib.OQS_KEM_new.restype = ctypes.POINTER(_OqsKem)
_lib.OQS_KEM_keypair.argtypes = [
    ctypes.POINTER(_OqsKem),
    ctypes.c_char_p,
    ctypes.c_char_p,
]
_lib.OQS_KEM_keypair.restype = ctypes.c_int
_lib.OQS_KEM_encaps.argtypes = [
    ctypes.POINTER(_OqsKem),
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
_lib.OQS_KEM_encaps.restype = ctypes.c_int
_lib.OQS_KEM_decaps.argtypes = [
    ctypes.POINTER(_OqsKem),
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
_lib.OQS_KEM_decaps.restype = ctypes.c_int

_kem = _lib.OQS_KEM_new(_MLKEM_ALG)
if not _kem:
    raise RuntimeError("OQS_KEM_new(ML-KEM-768) returned NULL: algorithm disabled")
_verify_kem_struct(_kem.contents)


def _mlkem_keypair() -> Tuple[bytes, bytes]:
    pk_buf = ctypes.create_string_buffer(MLKEM_PK_LEN)
    sk_buf = ctypes.create_string_buffer(MLKEM_SK_LEN)
    if _lib.OQS_KEM_keypair(_kem, pk_buf, sk_buf) != _OQS_SUCCESS:
        raise MLKEMKeyCheckFailed("liboqs ML-KEM-768 keypair failed")
    return bytes(pk_buf.raw), bytes(sk_buf.raw)


def _mlkem_encaps(mlkem_pk: bytes) -> Tuple[bytes, bytes]:
    ct_buf = ctypes.create_string_buffer(MLKEM_CT_LEN)
    ss_buf = ctypes.create_string_buffer(MLKEM_SS_LEN)
    if _lib.OQS_KEM_encaps(_kem, ct_buf, ss_buf, mlkem_pk) != _OQS_SUCCESS:
        raise MLKEMKeyCheckFailed("liboqs ML-KEM-768 encaps failed")
    return bytes(ct_buf.raw), bytes(ss_buf.raw)


def _mlkem_decaps(mlkem_sk: bytes, c_mlkem: bytes) -> bytes:
    ss_buf = ctypes.create_string_buffer(MLKEM_SS_LEN)
    if _lib.OQS_KEM_decaps(_kem, ss_buf, c_mlkem, mlkem_sk) != _OQS_SUCCESS:
        raise MLKEMKeyCheckFailed("MLKEM_KEY_CHECK_FAILED")
    return bytes(ss_buf.raw)


def x25519_ecdh(x25519_sk: bytes, x25519_pk: bytes) -> bytes:
    """Raw X25519 ECDH shared secret (32B). Exposed for the RFC 7748 vector."""
    if len(x25519_sk) != X25519_LEN:
        raise ValueError(f"x25519_sk must be 32B, got {len(x25519_sk)}")
    if len(x25519_pk) != X25519_LEN:
        raise ValueError(f"x25519_pk must be 32B, got {len(x25519_pk)}")
    try:
        sk = x25519.X25519PrivateKey.from_private_bytes(x25519_sk)
        pk = x25519.X25519PublicKey.from_public_bytes(x25519_pk)
    except (ValueError, InvalidKey) as exc:
        raise ValueError(f"invalid X25519 key material: {exc}") from exc
    try:
        return sk.exchange(pk)
    except ValueError as exc:
        raise LowOrderX25519("X25519 exchange produced an all-zero secret (low-order point)") from exc


def is_all_zero(data: bytes) -> bool:
    """True when data is all zero bytes (constant-time compare)."""
    return hmac.compare_digest(data, bytes(len(data)))


def _combine(k_mlkem: bytes, k_x25519: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=K_HYBRID_LEN, salt=b"", info=_HKDF_INFO)
    return hkdf.derive(k_mlkem + k_x25519)


def _derive_x25519_sk(sk_input: bytes) -> bytes:
    """Derive a deterministic X25519 secret key from sk_input via HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=X25519_LEN,
        salt=b"xfsh-x25519-keygen",
        info=sk_input,
    )
    return hkdf.derive(b"")


def hybrid_keygen() -> KeyPair:
    """Generate hybrid (ML-KEM-768 + X25519) keypair. CSPRNG via liboqs/OS."""
    mlkem_pk, mlkem_sk = _mlkem_keypair()
    x_sk = x25519.X25519PrivateKey.generate()
    x_sk_raw = x_sk.private_bytes_raw()
    x_pk_raw = x_sk.public_key().public_bytes_raw()
    return KeyPair(
        public=Recipient(hybrid_pk=mlkem_pk + x_pk_raw),
        private=mlkem_sk + x_sk_raw,
    )


def hybrid_encap(
    hybrid_pk: bytes,
    _eph_x25519_sk: Optional[bytes] = None,
) -> Tuple[bytes, bytes]:
    """Encapsulate to hybrid_pk. Returns (C_hybrid: 1120B, K_hybrid: 32B).

    If _eph_x25519_sk is None, a fresh ephemeral X25519 key is generated
    (randomized mode).  If _eph_x25519_sk is provided (32B), it is used
    directly for deterministic encapsulation.
    """
    if len(hybrid_pk) != HYBRID_PK_LEN:
        raise ValueError(f"hybrid_pk must be {HYBRID_PK_LEN}B, got {len(hybrid_pk)}")
    mlkem_pk, peer_x_pk = hybrid_pk[:MLKEM_PK_LEN], hybrid_pk[MLKEM_PK_LEN:]
    if is_all_zero(mlkem_pk):
        raise ValueError(
            "ML-KEM public key is all-zero: this is a classical-only (X25519) key and cannot "
            "receive a hybrid encapsulation"
        )
    c_mlkem, k_mlkem = _mlkem_encaps(mlkem_pk)
    if _eph_x25519_sk is None:
        eph_sk = x25519.X25519PrivateKey.generate()
    else:
        if len(_eph_x25519_sk) != X25519_LEN:
            raise ValueError(f"_eph_x25519_sk must be {X25519_LEN}B, got {len(_eph_x25519_sk)}")
        eph_sk = x25519.X25519PrivateKey.from_private_bytes(_eph_x25519_sk)
    c_x25519 = eph_sk.public_key().public_bytes_raw()
    k_x25519 = eph_sk.exchange(x25519.X25519PublicKey.from_public_bytes(peer_x_pk))
    return c_mlkem + c_x25519, _combine(k_mlkem, k_x25519)


def hybrid_decaps(hybrid_sk: bytes, c_hybrid: bytes) -> bytes:
    """Decapsulate C_hybrid. Returns K_hybrid: 32B.

    Raises MLKEMKeyCheckFailed when liboqs reports decapsulation failure;
    ValueError on malformed input lengths (never reads out of bounds).
    """
    if len(hybrid_sk) != HYBRID_SK_LEN:
        raise ValueError(f"hybrid_sk must be {HYBRID_SK_LEN}B, got {len(hybrid_sk)}")
    if len(c_hybrid) != C_HYBRID_LEN:
        raise ValueError(f"C_hybrid must be {C_HYBRID_LEN}B, got {len(c_hybrid)}")
    mlkem_sk, x_sk_raw = hybrid_sk[:MLKEM_SK_LEN], hybrid_sk[MLKEM_SK_LEN:]
    c_mlkem, c_x25519 = c_hybrid[:MLKEM_CT_LEN], c_hybrid[MLKEM_CT_LEN:]
    k_mlkem = _mlkem_decaps(mlkem_sk, c_mlkem)
    k_x25519 = x25519_ecdh(x_sk_raw, c_x25519)
    return _combine(k_mlkem, k_x25519)


def classical_only_encap(
    x25519_pk: bytes,
    _eph_x25519_sk: Optional[bytes] = None,
) -> Tuple[bytes, bytes]:
    """X25519-only encapsulation (classical-only mode).

    Returns (C_x25519: 32B, K: 32B) where K is derived from X25519 shared
    secret alone. This matches classical_only_decaps so the header can be
    encrypted with this key and decrypted with the classical-only path.

    Args:
        x25519_pk: 32-byte X25519 public key of the recipient.
        _eph_x25519_sk: optional 32-byte ephemeral X25519 secret key. If None,
            a fresh ephemeral key is generated.

    Returns:
        Tuple of (C_x25519: 32B, K: 32B).
    """
    if len(x25519_pk) != X25519_LEN:
        raise ValueError(f"x25519_pk must be {X25519_LEN}B, got {len(x25519_pk)}")
    if _eph_x25519_sk is None:
        eph_sk = x25519.X25519PrivateKey.generate()
    else:
        if len(_eph_x25519_sk) != X25519_LEN:
            raise ValueError(f"_eph_x25519_sk must be {X25519_LEN}B, got {len(_eph_x25519_sk)}")
        eph_sk = x25519.X25519PrivateKey.from_private_bytes(_eph_x25519_sk)
    c_x25519 = eph_sk.public_key().public_bytes_raw()
    k_x25519 = eph_sk.exchange(x25519.X25519PublicKey.from_public_bytes(x25519_pk))
    hkdf = HKDF(algorithm=hashes.SHA256(), length=K_HYBRID_LEN, salt=b"", info=_HKDF_INFO)
    return c_x25519, hkdf.derive(k_x25519)


def classical_only_decaps(hybrid_sk: bytes, c_x25519: bytes) -> bytes:
    """X25519-only decapsulation (classical_only mode).

    Returns K_hybrid: 32B derived from K_x25519 alone.
    """
    if len(hybrid_sk) != HYBRID_SK_LEN:
        raise ValueError(f"hybrid_sk must be {HYBRID_SK_LEN}B, got {len(hybrid_sk)}")
    if len(c_x25519) != X25519_LEN:
        raise ValueError(f"c_x25519 must be {X25519_LEN}B, got {len(c_x25519)}")
    x_sk_raw = hybrid_sk[MLKEM_SK_LEN:]
    k_x25519 = x25519_ecdh(x_sk_raw, c_x25519)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=K_HYBRID_LEN,
        salt=b"",
        info=_HKDF_INFO,
    )
    return hkdf.derive(k_x25519)
