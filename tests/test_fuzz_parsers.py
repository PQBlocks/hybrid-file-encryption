"""Property-based fuzzing of the hostile-input parsers (hypothesis).

Contract under test: given any bytes, the parsers either return a value or raise one of the
documented exceptions. Anything else (IndexError, UnicodeError, OverflowError, ...) is a bug.
For decrypt(), a mutated file either fails loudly or yields exactly the original plaintext.
"""

import base64

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pqblocks_files.encrypt import (
    decrypt,
    encrypt,
    extract_stanza_fields,
    parse_pfsh,
    read_chunk_nonce,
    split_header_mac,
)
from pqblocks_files.header import parse_header
from pqblocks_files.keys import keygen
from pqblocks_files.pqtypes import (
    ClassicalOnlyRejected,
    HeaderMACMismatch,
    MLKEMKeyCheckFailed,
    NonMonotonicCounter,
    TagVerificationFailed,
    TruncatedFile,
)

SETTINGS = settings(
    max_examples=400,
    deadline=None,
    database=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.large_base_example],
)

KP = keygen()
PLAINTEXT = b"fuzz plaintext " * 20
VALID_HYBRID = encrypt(PLAINTEXT, [KP.public])
VALID_CLASSICAL = encrypt(PLAINTEXT, [KP.public], classical_only=True)

PARSE_PFSH_ERRORS = (ValueError, TruncatedFile)
HEADER_ERRORS = (ValueError, HeaderMACMismatch)
DECRYPT_ERRORS = (
    ValueError, TruncatedFile, HeaderMACMismatch, TagVerificationFailed,
    NonMonotonicCounter, MLKEMKeyCheckFailed, ClassicalOnlyRejected,
)


def _mutate(base: bytes):
    """Valid file with a few random byte edits: flips, insertions, deletions, truncation."""
    edit = st.one_of(
        st.tuples(st.just("flip"), st.integers(0, len(base) - 1), st.integers(1, 255)),
        st.tuples(st.just("ins"), st.integers(0, len(base)), st.binary(min_size=1, max_size=8)),
        st.tuples(st.just("del"), st.integers(0, len(base) - 1), st.integers(1, 64)),
        st.tuples(st.just("cut"), st.integers(0, len(base)), st.just(0)),
    )

    def apply(edits):
        data = bytearray(base)
        for kind, pos, arg in edits:
            pos = min(pos, len(data))
            if kind == "flip" and pos < len(data):
                data[pos] ^= arg
            elif kind == "ins":
                data[pos:pos] = arg
            elif kind == "del":
                del data[pos:pos + arg]
            elif kind == "cut":
                del data[pos:]
        return bytes(data)

    return st.lists(edit, min_size=1, max_size=4).map(apply)


header_lines = st.one_of(
    st.binary(max_size=60),
    st.builds(lambda a, b: b"-> " + a + b" " + b, st.binary(max_size=60).map(base64.b64encode),
              st.binary(max_size=60).map(base64.b64encode)),
    st.builds(lambda a: b"-> " + a, st.binary(max_size=80)),
    st.binary(max_size=1600).map(base64.b64encode),
    st.builds(lambda a: b"=== " + a, st.binary(max_size=24).map(base64.b64encode)),
    st.just(b""),
)
fake_headers = st.lists(header_lines, max_size=6).map(
    lambda ls: b"pfsh-encryption.org/v1\n" + b"\n".join(ls) + b"\n")


@SETTINGS
@given(st.binary(max_size=4096))
def test_parse_pfsh_random_bytes(data):
    try:
        parse_pfsh(data)
    except PARSE_PFSH_ERRORS:
        pass


@SETTINGS
@given(_mutate(VALID_HYBRID))
def test_parse_pfsh_mutated_valid_file(data):
    try:
        header, body, end = parse_pfsh(data)
    except PARSE_PFSH_ERRORS:
        return
    assert isinstance(header, bytes) and isinstance(body, bytes) and isinstance(end, bytes)


@SETTINGS
@given(st.one_of(st.binary(max_size=4096), fake_headers, _mutate(VALID_HYBRID), _mutate(VALID_CLASSICAL)))
def test_extract_stanza_fields_and_split_header_mac(data):
    for fn in (extract_stanza_fields, split_header_mac):
        try:
            fn(data)
        except ValueError:
            pass


@SETTINGS
@given(st.one_of(st.binary(max_size=2048), fake_headers, _mutate(VALID_HYBRID), _mutate(VALID_CLASSICAL)))
def test_parse_header_hostile_input(data):
    try:
        parse_header(data, [KP])
    except HEADER_ERRORS:
        pass


@SETTINGS
@given(st.binary(max_size=64), st.integers(-5, 80))
def test_read_chunk_nonce_hostile_input(body, offset):
    try:
        nonce, flag = read_chunk_nonce(body, offset)
    except TruncatedFile:
        return
    assert len(nonce) == 12 and flag in (0, 1)


@pytest.mark.parametrize("valid, require_pq", [(VALID_HYBRID, True), (VALID_CLASSICAL, False)])
def test_decrypt_mutated_file_fails_loudly_or_returns_original(valid, require_pq):
    @SETTINGS
    @given(_mutate(valid))
    def run(data):
        try:
            out = decrypt(data, KP, require_pq=require_pq)
        except DECRYPT_ERRORS:
            return
        assert out == PLAINTEXT

    run()


@SETTINGS
@given(st.one_of(st.binary(max_size=4096), fake_headers))
def test_decrypt_random_input_only_documented_errors(data):
    try:
        decrypt(data, KP, require_pq=False)
    except DECRYPT_ERRORS:
        pass
