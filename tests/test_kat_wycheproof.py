"""Wycheproof ML-KEM-768 KATs .

Structural + decapsulation known-answer checks against the real Wycheproof
vectors in tests/kats/wycheproof/. Decapsulation KATs run through liboqs
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

KATS_DIR = os.path.join(os.path.dirname(__file__), "kats", "wycheproof")


def _load(name: str) -> dict:
    with open(os.path.join(KATS_DIR, name), encoding="utf-8") as fh:
        return json.load(fh)


def _all_tests(doc: dict) -> list:
    out = []
    for group in doc["testGroups"]:
        out.extend(group["tests"])
    return out


def _b(hexstr: str, nbytes: int, label: str) -> bytes:
    raw = bytes.fromhex(hexstr)
    assert len(raw) == nbytes, "%s: %d bytes, want %d" % (label, len(raw), nbytes)
    return raw


def test_wycheproof_keygen_seed_sizes() -> None:
    """Seed-derived keygen vectors have ML-KEM-768 sizes (seed 64B)."""
    tests = _all_tests(_load("mlkem_768_keygen_seed_test.json"))
    assert len(tests) > 0
    for t in tests:
        if t.get("result", "valid") != "valid":
            continue
        _b(t["seed"], 64, "tc%d seed" % t["tcId"])
        _b(t["ek"], MLKEM_PK_LEN, "tc%d ek" % t["tcId"])
        _b(t["dk"], MLKEM_SK_LEN, "tc%d dk" % t["tcId"])


def test_wycheproof_encaps_vector_sizes() -> None:
    """Valid encaps vectors carry full-size ek/c/K; invalid ones are marked."""
    tests = _all_tests(_load("mlkem_768_encaps_test.json"))
    assert len(tests) > 0
    n_valid = 0
    for t in tests:
        if t.get("result", "valid") != "valid":
            assert (
                not t.get("c")
                or not t.get("K")
                or t.get("flags")
                or t.get("comment")
            ), "tc%d invalid without marker" % t["tcId"]
            continue
        n_valid += 1
        _b(t["ek"], MLKEM_PK_LEN, "tc%d ek" % t["tcId"])
        _b(t["c"], MLKEM_CT_LEN, "tc%d c" % t["tcId"])
        _b(t["K"], MLKEM_SS_LEN, "tc%d K" % t["tcId"])
    assert n_valid > 0, "no valid encaps vectors found"


def test_wycheproof_ml_kem_vector_sizes() -> None:
    """Main ml_kem vectors: sizes hold where fields are present."""
    tests = _all_tests(_load("mlkem_768_test.json"))
    assert len(tests) > 0
    for t in tests:
        if t.get("result", "valid") != "valid":
            continue
        if t.get("seed"):
            _b(t["seed"], 64, "tc%d seed" % t["tcId"])
        _b(t["ek"], MLKEM_PK_LEN, "tc%d ek" % t["tcId"])
        _b(t["c"], MLKEM_CT_LEN, "tc%d c" % t["tcId"])
        _b(t["K"], MLKEM_SS_LEN, "tc%d K" % t["tcId"])


def test_wycheproof_decaps_kat_liboqs() -> None:
    """liboqs decaps of valid semi-expanded vectors reproduces K exactly."""
    tests = _all_tests(_load("mlkem_768_semi_expanded_decaps_test.json"))
    assert len(tests) > 0
    n_checked = 0
    for t in tests:
        if t.get("result", "valid") != "valid":
            continue
        if t.get("flags"):
            continue
        dk = _b(t["dk"], MLKEM_SK_LEN, "tc%d dk" % t["tcId"])
        c = _b(t["c"], MLKEM_CT_LEN, "tc%d c" % t["tcId"])
        expected = _b(t["K"], MLKEM_SS_LEN, "tc%d K" % t["tcId"])
        assert _mlkem_decaps(dk, c) == expected, "tc%d K mismatch" % t["tcId"]
        n_checked += 1
    assert n_checked > 0, "no valid decaps vectors checked"


def test_wycheproof() -> None:
    """Suite entry: all Wycheproof files present with test groups."""
    for name in (
        "mlkem_768_test.json",
        "mlkem_768_keygen_seed_test.json",
        "mlkem_768_encaps_test.json",
        "mlkem_768_semi_expanded_decaps_test.json",
    ):
        doc = _load(name)
        assert doc["testGroups"], name
