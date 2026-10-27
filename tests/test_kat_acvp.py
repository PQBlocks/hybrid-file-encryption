"""NIST ACVP ML-KEM-768 KATs .

Structural + decapsulation known-answer checks against the ACVP-style
vectors in tests/kats/acvp/. Decapsulation KATs run through liboqs
(src/kem.py _mlkem_decaps), the same audited backend the product uses.
This is a regression net, not a verification claim.
"""

import json
import os

from pqblocks_files.kem import (
    MLKEM_CT_LEN,
    MLKEM_PK_LEN,
    MLKEM_SK_LEN,
    MLKEM_SS_LEN,
    _mlkem_decaps,
)

KATS_DIR = os.path.join(os.path.dirname(__file__), "kats", "acvp")
ENCAP_FILE = os.path.join("ML-KEM-768_encapDecap", "internalProjection.json")
KEYGEN_FILE = os.path.join("ML-KEM-768_keyGen", "internalProjection.json")


def _load(rel: str) -> dict:
    with open(os.path.join(KATS_DIR, rel), encoding="utf-8") as fh:
        return json.load(fh)


def _all_tests(doc: dict) -> list:
    out = []
    for group in doc["testGroups"]:
        if group.get("parameterSet") != "ML-KEM-768":
            continue
        for t in group["tests"]:
            if all(f in t for f in ("tcId", "parameterSet")):
                out.append(t)
    return out


def _b(hexstr: str, nbytes: int, label: str) -> bytes:
    raw = bytes.fromhex(hexstr)
    assert len(raw) == nbytes, "%s: %d bytes, want %d" % (label, len(raw), nbytes)
    return raw


def _with_fields(doc: dict, *fields: str) -> list:
    """Tests in ML-KEM-768 groups that carry all named fields (ACVP groups
    mix schemas per function; assert only on what the group contains)."""
    out = []
    for group in doc["testGroups"]:
        if group.get("parameterSet") != "ML-KEM-768":
            continue
        for t in group["tests"]:
            # Ensure all required fields are present before processing
            if all(f in t for f in fields):
                out.append(t)
    return out


def test_acvp_keygen_sizes() -> None:
    """ACVP keyGen vectors have ML-KEM-768 sizes (z/d 32B)."""
    tests = _with_fields(_load(KEYGEN_FILE), "z", "d", "ek", "dk")
    assert len(tests) > 0
    for t in tests:
        if t.get("deferred"):
            continue
        _b(t["z"], 32, "tc%s z" % t["tcId"])
        _b(t["d"], 32, "tc%s d" % t["tcId"])
        _b(t["ek"], MLKEM_PK_LEN, "tc%s ek" % t["tcId"])
        _b(t["dk"], MLKEM_SK_LEN, "tc%s dk" % t["tcId"])


def test_acvp_encapdecap_sizes() -> None:
    """ACVP encapDecap vectors have ML-KEM-768 sizes (m/k 32B)."""
    tests = _with_fields(_load(ENCAP_FILE), "ek", "dk", "c", "k", "m")
    assert len(tests) > 0
    for t in tests:
        if t.get("deferred"):
            continue
        _b(t["ek"], MLKEM_PK_LEN, "tc%s ek" % t["tcId"])
        _b(t["dk"], MLKEM_SK_LEN, "tc%s dk" % t["tcId"])
        _b(t["c"], MLKEM_CT_LEN, "tc%s c" % t["tcId"])
        _b(t["k"], MLKEM_SS_LEN, "tc%s k" % t["tcId"])
        _b(t["m"], 32, "tc%s m" % t["tcId"])


def test_acvp_decap_kat_liboqs() -> None:
    """liboqs decaps of ACVP encapDecap vectors reproduces k exactly."""
    tests = _with_fields(_load(ENCAP_FILE), "dk", "c", "k")
    n_checked = 0
    for t in tests:
        if t.get("deferred"):
            continue
        dk = _b(t["dk"], MLKEM_SK_LEN, "tc%s dk" % t["tcId"])
        c = _b(t["c"], MLKEM_CT_LEN, "tc%s c" % t["tcId"])
        expected = _b(t["k"], MLKEM_SS_LEN, "tc%s k" % t["tcId"])
        assert _mlkem_decaps(dk, c) == expected, "tc%s k mismatch" % t["tcId"]
        n_checked += 1
    assert n_checked > 0, "no ACVP decap vectors checked"


def test_acvp() -> None:
    """Suite entry: both ACVP vector files present with test groups."""
    for rel in (ENCAP_FILE, KEYGEN_FILE):
        doc = _load(rel)
        assert doc["testGroups"], rel
