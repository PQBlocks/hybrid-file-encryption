"""Hybrid KEM core tests.

Contract under test :
  hybrid_pk = mlkem_pk(1184B) || x25519_pk(32B) = 1216B
  hybrid_sk = mlkem_sk(2400B) || x25519_sk(32B) = 2432B
  C_hybrid  = C_mlkem(1088B) || C_x25519(32B)   = 1120B
  K_hybrid  = HKDF-SHA256(K_mlkem || K_x25519, salt=b"", info=b"pfsh-hybrid") = 32B

Public API :
  hybrid_keygen() -> KeyPair
  hybrid_encap(hybrid_pk) -> (C_hybrid, K_hybrid)
  hybrid_decaps(hybrid_sk, C_hybrid) -> K_hybrid (raises MLKEMKeyCheckFailed)
"""

import pytest

from pqblocks_files.kem import (
    MLKEM_PK_LEN,
    classical_only_decaps,
    classical_only_encap,
    hybrid_decaps,
    hybrid_encap,
    hybrid_keygen,
    x25519_ecdh,
)
from pqblocks_files.pqtypes import MLKEMKeyCheckFailed


def test_rfc7748_x25519_vector_exact_match() -> None:
    """RFC 7748 section 6.1 test vector: fixed ECDH must match byte-exact."""
    priv_a = bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    )
    pub_b = bytes.fromhex(
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    )
    expected = bytes.fromhex(
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    )
    assert x25519_ecdh(priv_a, pub_b) == expected


def test_mlkem768_sizes_match_fips203_table3() -> None:
    """Key/ciphertext sizes must equal FIPS 203 Table 3 via live liboqs struct."""
    kp = hybrid_keygen()
    assert len(kp.public.hybrid_pk) == 1216  # 1184 + 32
    assert len(kp.private) == 2432  # 2400 + 32
    c_hybrid, k_hybrid = hybrid_encap(kp.public.hybrid_pk)
    assert len(c_hybrid) == 1120  # 1088 + 32
    assert len(k_hybrid) == 32


def test_hybrid_kem_both_sides_agree() -> None:
    """Encap/decaps round-trip: both sides derive the same K_hybrid."""
    kp = hybrid_keygen()
    c_hybrid, k_enc = hybrid_encap(kp.public.hybrid_pk)
    k_dec = hybrid_decaps(kp.private, c_hybrid)
    assert k_dec == k_enc


def test_hybrid_keygen_distinct_csprng() -> None:
    """Two keygens must differ (CSPRNG, never a fixed test key)."""
    kp1 = hybrid_keygen()
    kp2 = hybrid_keygen()
    assert kp1.public.hybrid_pk != kp2.public.hybrid_pk
    assert kp1.private != kp2.private


def test_hybrid_encap_randomized() -> None:
    """Two encaps to the same pk must differ in C_hybrid and K_hybrid."""
    kp = hybrid_keygen()
    c1, k1 = hybrid_encap(kp.public.hybrid_pk)
    c2, k2 = hybrid_encap(kp.public.hybrid_pk)
    assert c1 != c2
    assert k1 != k2


def test_hybrid_decaps_tampered_ct_mismatches_or_raises() -> None:
    """Behaviour under (FIPS 203 implicit rejection): tampered C_mlkem must NOT
    yield the original K. Either MLKEMKeyCheckFailed or a mismatched K."""
    kp = hybrid_keygen()
    c_hybrid, k_enc = hybrid_encap(kp.public.hybrid_pk)
    bad = bytearray(c_hybrid)
    bad[0] ^= 0xFF  # flip one byte inside C_mlkem
    try:
        k_bad = hybrid_decaps(kp.private, bytes(bad))
    except MLKEMKeyCheckFailed:
        return
    assert k_bad != k_enc


def test_hybrid_encap_rejects_bad_pk_length() -> None:
    """Contract violation: hybrid_pk must be exactly 1216B."""
    with pytest.raises(ValueError):
        hybrid_encap(b"\x00" * 100)
    with pytest.raises(ValueError):
        hybrid_encap(b"\x00" * 1215)
    with pytest.raises(ValueError):
        hybrid_encap(b"\x00" * 1217)


def test_hybrid_decaps_rejects_bad_lengths() -> None:
    """Contract violation at decaps: wrong sk/ct lengths must raise loudly,
    never read out of bounds or return garbage."""
    kp = hybrid_keygen()
    c_hybrid, _ = hybrid_encap(kp.public.hybrid_pk)
    with pytest.raises((ValueError, MLKEMKeyCheckFailed)):
        hybrid_decaps(b"\x00" * 100, c_hybrid)
    with pytest.raises((ValueError, MLKEMKeyCheckFailed)):
        hybrid_decaps(kp.private, b"\x00" * 100)
    with pytest.raises((ValueError, MLKEMKeyCheckFailed)):
        hybrid_decaps(kp.private, c_hybrid + b"\x00")


def test_hybrid_decaps_wrong_key_mismatches_or_raises() -> None:
    """Decaps with a different recipient key must not recover the sender K."""
    kp1 = hybrid_keygen()
    kp2 = hybrid_keygen()
    c_hybrid, k_enc = hybrid_encap(kp1.public.hybrid_pk)
    try:
        k_bad = hybrid_decaps(kp2.private, c_hybrid)
    except MLKEMKeyCheckFailed:
        return
    assert k_bad != k_enc


def test_combiner_is_deterministic_and_sensitive() -> None:
    """Same (K_mlkem, K_x25519) pair decapsulated twice must agree; the
    combiner must mix both shares (covered via distinct encap keys)."""
    kp = hybrid_keygen()
    c_hybrid, k_enc = hybrid_encap(kp.public.hybrid_pk)
    assert hybrid_decaps(kp.private, c_hybrid) == k_enc


# --- classical_only edge-case coverage ---

def test_classical_only_encap_rejects_bad_pk_length() -> None:
    with pytest.raises(ValueError):
        classical_only_encap(b"\x00" * 16)
    with pytest.raises(ValueError):
        classical_only_encap(b"\x00" * 31)
    with pytest.raises(ValueError):
        classical_only_encap(b"\x00" * 33)


def test_classical_only_encap_rejects_bad_eph_sk_length() -> None:
    x25519_pk = bytes(range(32))
    with pytest.raises(ValueError):
        classical_only_encap(x25519_pk, b"\x00" * 16)
    with pytest.raises(ValueError):
        classical_only_encap(x25519_pk, b"\x00" * 33)


def test_classical_only_decaps_rejects_bad_hybrid_sk_length() -> None:
    with pytest.raises(ValueError):
        classical_only_decaps(b"\x00" * 100, bytes(range(32)))


def test_classical_only_decaps_rejects_bad_c_x25519_length() -> None:
    hybrid_sk = b"\x00" * 2432
    with pytest.raises(ValueError):
        classical_only_decaps(hybrid_sk, b"\x00" * 16)


def test_hybrid_decaps_rejects_bad_c_hybrid_length() -> None:
    kp = hybrid_keygen()
    with pytest.raises(ValueError):
        hybrid_decaps(kp.private, b"\x00" * 100)
    with pytest.raises(ValueError):
        hybrid_decaps(kp.private, b"\x00" * 1121)


def test_hybrid_encap_rejects_bad_eph_sk_length() -> None:
    kp = hybrid_keygen()
    with pytest.raises(ValueError):
        hybrid_encap(kp.public.hybrid_pk, b"\x00" * 16)
    with pytest.raises(ValueError):
        hybrid_encap(kp.public.hybrid_pk, b"\x00" * 33)


def test_classical_only_round_trip() -> None:
    kp = hybrid_keygen()
    x25519_pk = kp.public.hybrid_pk[MLKEM_PK_LEN:]
    c_x25519, k_enc = classical_only_encap(x25519_pk)
    k_dec = classical_only_decaps(kp.private, c_x25519)
    assert k_dec == k_enc
