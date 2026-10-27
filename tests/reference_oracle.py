"""Reference oracle for the pfsh v1 file format (test support, not shipped in the package).

Independent, plain implementation of the file writer/reader. Uses only audited libraries for
primitives. Serves as the equivalence oracle for the file-format writer: given the same file_key,
the chunk body it produces must be bit-identical to pqblocks_files.encrypt output.

It accepts a caller-chosen file_key on purpose, which is why it lives with the tests only.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as hmac_mod
import os
from typing import List, Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pqblocks_files import kem as kem_mod
from pqblocks_files.pqtypes import (
    HeaderMACMismatch,
    KeyPair,
    NonMonotonicCounter,
    Recipient,
    TagVerificationFailed,
    TruncatedFile,
)

_VERSION_LINE = b"pfsh-encryption.org/v1\n"
_CHUNK = 65536
_WRAP_NONCE = bytes(11) + b"\x00"
_END_MARKER = b"--- " + base64.b64encode(bytes(16)) + b"\n"


def _hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=info
    ).derive(ikm)


def _nonce(counter: int, final: bool) -> bytes:
    return (
        counter.to_bytes(8, "big")
        + (b"\x01" if final else b"\x00")
        + b"\x00\x00\x00"
    )


def _build_stanza(rec: Recipient, file_key: bytes) -> bytes:
    c_hybrid, k_hybrid = kem_mod.hybrid_encap(rec.hybrid_pk)
    wrap_key = _hkdf(k_hybrid, b"", b"wrap")
    wrapped = ChaCha20Poly1305(wrap_key).encrypt(_WRAP_NONCE, file_key, b"")
    c_mlkem, c_x = c_hybrid[: kem_mod.MLKEM_CT_LEN], c_hybrid[kem_mod.MLKEM_CT_LEN :]
    return (
        b"-> "
        + base64.b64encode(wrapped)
        + b" "
        + base64.b64encode(c_x)
        + b"\n"
        + base64.b64encode(c_mlkem)
        + b"\n"
    )


def encrypt(
    plaintext: bytes,
    recipients: List[Recipient],
    file_key: Optional[bytes] = None,
    classical_only: bool = False,
) -> bytes:
    if classical_only:
        raise ValueError("reference oracle implements hybrid mode only")
    if file_key is None:
        file_key = os.urandom(16)
    if len(file_key) != 16:
        raise ValueError("file_key must be 16 bytes")
    stanzas = b"".join(_build_stanza(r, file_key) for r in recipients)
    header_body = _VERSION_LINE + stanzas
    mac_key = _hkdf(file_key, b"", b"header")
    mac = hmac_mod.new(mac_key, header_body, hashlib.sha256).digest()[:16]
    header = header_body + b"=== " + base64.b64encode(mac) + b"\n"
    pieces = [
        plaintext[i : i + _CHUNK] for i in range(0, len(plaintext), _CHUNK)
    ]
    if not pieces:
        pieces = [b""]
    body = b""
    for idx, piece in enumerate(pieces):
        nonce = _nonce(idx, idx == len(pieces) - 1)
        key = _hkdf(file_key, nonce, b"payload")
        body += nonce + ChaCha20Poly1305(key).encrypt(nonce, piece, b"")
    return header + body + _END_MARKER


def _split_file(data: bytes) -> Tuple[bytes, bytes]:
    if not data.startswith(_VERSION_LINE):
        raise ValueError("missing version line")
    if not data.endswith(_END_MARKER):
        raise TruncatedFile("missing end marker")
    inner = data[: -len(_END_MARKER)]
    lines = inner.split(b"\n")
    mac_at = next(
        (i for i, ln in enumerate(lines) if ln.startswith(b"=== ")), None
    )
    if mac_at is None:
        raise ValueError("missing header MAC line")
    header = b"\n".join(lines[: mac_at + 1]) + b"\n"
    return header, inner[len(header) :]


def decrypt(data: bytes, keypair: KeyPair) -> bytes:
    header, body = _split_file(data)
    lines = header.split(b"\n")
    mac_at = next(i for i, ln in enumerate(lines) if ln.startswith(b"=== "))
    stored = base64.b64decode(lines[mac_at][4:], validate=True)
    header_body = b"\n".join(lines[:mac_at]) + b"\n"
    file_key: Optional[bytes] = None
    i = 1
    while i < mac_at and file_key is None:
        arg = lines[i]
        if not arg.startswith(b"-> "):
            raise ValueError("malformed stanza")
        w_b64, x_b64 = arg[3:].split(b" ")
        full = lines[i + 1]
        c_hybrid = base64.b64decode(full, validate=True) + base64.b64decode(
            x_b64, validate=True
        )
        try:
            k_hybrid = kem_mod.hybrid_decaps(keypair.private, c_hybrid)
        except Exception:
            i += 2
            continue
        wrap_key = _hkdf(k_hybrid, b"", b"wrap")
        try:
            cand = ChaCha20Poly1305(wrap_key).decrypt(
                _WRAP_NONCE, base64.b64decode(w_b64, validate=True), b""
            )
        except Exception:
            i += 2
            continue
        mac_key = _hkdf(cand, b"", b"header")
        expect = hmac_mod.new(mac_key, header_body, hashlib.sha256).digest()[:16]
        if hmac_mod.compare_digest(expect, stored):
            file_key = cand
        i += 2
    if file_key is None:
        raise HeaderMACMismatch("no stanza decrypts under this key")
    out = b""
    off = 0
    want = 0
    done = False
    while off < len(body):
        if len(body) - off < 28:
            raise TruncatedFile("short chunk frame")
        nonce = body[off : off + 12]
        if nonce[9:12] != b"\x00\x00\x00" or nonce[8] not in (0, 1):
            raise TruncatedFile("bad nonce framing")
        if int.from_bytes(nonce[:8], "big") != want:
            raise NonMonotonicCounter("chunk counter out of order")
        final = nonce[8] == 1
        rest = len(body) - off - 28
        take = rest if rest < _CHUNK else _CHUNK
        if not final and take != _CHUNK:
            raise TruncatedFile("short non-final chunk")
        key = _hkdf(file_key, nonce, b"payload")
        try:
            out += ChaCha20Poly1305(key).decrypt(
                nonce, body[off + 12 : off + 12 + take + 16], b""
            )
        except Exception as exc:
            if final:
                for alt_len in range(take - 1, max(-1, take - 1024), -1):
                    cand = body[off + 12 : off + 12 + alt_len + 16]
                    try:
                        ChaCha20Poly1305(key).decrypt(nonce, cand, b"")
                        raise TruncatedFile("trailing bytes after final chunk")
                    except TruncatedFile:
                        raise
                    except Exception:
                        continue
            raise TagVerificationFailed("chunk tag mismatch") from exc
        off += 12 + take + 16
        want += 1
        if final:
            if off != len(body):
                raise TruncatedFile("trailing bytes after final chunk")
            done = True
            break
    if not done:
        raise TruncatedFile("no final chunk")
    return out
