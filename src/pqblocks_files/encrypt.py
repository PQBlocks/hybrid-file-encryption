"""pfsh v1 file writer and reader.

Public API:
  encrypt(plaintext, recipients, classical_only=False) -> bytes
  decrypt(pfsh_bytes, keypair, require_pq=True) -> bytes
  decrypt_with_mode(pfsh_bytes, keypair, require_pq=True) -> DecryptResult(plaintext, mode)

The file key is always drawn fresh from the OS CSPRNG inside encrypt(); callers cannot supply it.
decrypt() refuses files that this key can only open through a classical-only (X25519) stanza
unless the caller passes require_pq=False.

Wire layout:
  pfsh_file = header body end
  header    = version-line 1*recipient-stanza header-mac-line
  body      = *chunk, chunk = 12B nonce || ciphertext || 16B tag
  end       = "--- " BASE64(16 zero bytes) LF

Framing helpers:
  parse_pfsh, split_header_mac, extract_stanza_fields, read_chunk_nonce.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as hmac_mod
import os
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from pqblocks_files import kem as kem_mod
from pqblocks_files.ae import chacha20poly1305_decrypt, derive_payload_key
from pqblocks_files.header import _encode_header
from pqblocks_files.pqtypes import (
    ClassicalOnlyRejected,
    HeaderMACMismatch,
    KeyPair,
    LowOrderX25519,
    MLKEMKeyCheckFailed,
    NonMonotonicCounter,
    Recipient,
    TagVerificationFailed,
    TruncatedFile,
)

VERSION_LINE = b"pfsh-encryption.org/v1\n"
CHUNK_SIZE = 65536
NONCE_LEN = 12
TAG_LEN = 16
WRAP_NONCE = bytes(11) + b"\x00"
END_MARKER = b"--- " + base64.b64encode(b"\x00" * 16) + b"\n"
MODE_HYBRID = "hybrid"        # the file key was opened through an ML-KEM-768 + X25519 stanza
MODE_CLASSICAL = "classical"  # the file key was opened through an X25519-only stanza


@dataclass(frozen=True)
class DecryptResult:
    plaintext: bytes = field(repr=False)
    mode: str


@dataclass(frozen=True)
class Stanza:
    wrapped_fk: bytes
    c_x25519: bytes
    c_mlkem: Optional[bytes]


def _b64decode(field: bytes, what: str) -> bytes:
    try:
        return base64.b64decode(field.strip(), validate=True)
    except Exception as exc:
        raise ValueError(f"invalid base64 in {what}: {exc}") from exc


def read_chunk_nonce(body: bytes, offset: int) -> Tuple[bytes, int]:
    """Return (nonce, flag) for the frame at offset. Malformed framing is TruncatedFile."""
    if offset < 0 or len(body) - offset < NONCE_LEN:
        raise TruncatedFile(f"short nonce at offset {offset}")
    nonce = body[offset : offset + NONCE_LEN]
    flag = nonce[8]
    if flag not in (0x00, 0x01):
        raise TruncatedFile(f"bad chunk flag byte 0x{flag:02x} at offset {offset}")
    if nonce[9:12] != b"\x00\x00\x00":
        raise TruncatedFile(f"nonzero reserved nonce bytes at offset {offset}")
    return nonce, flag


def split_header_mac(header: bytes) -> Tuple[bytes, bytes]:
    """Split header into (header_body, stored_mac). header_body excludes the MAC line."""
    lines = header.split(b"\n")
    mac_at = next(
        (i for i, ln in enumerate(lines) if ln.startswith(b"=== ")), None
    )
    if mac_at is None:
        raise ValueError("missing header MAC line")
    stored_mac = _b64decode(lines[mac_at][4:], "header MAC")
    if len(stored_mac) != TAG_LEN:
        raise ValueError(f"header MAC must be {TAG_LEN}B")
    header_body = b"\n".join(lines[:mac_at]) + b"\n"
    return header_body, stored_mac


def extract_stanza_fields(header: bytes) -> List[Stanza]:
    """Parse recipient stanzas between the version line and the MAC line."""
    lines = header.split(b"\n")
    mac_at = next(
        (i for i, ln in enumerate(lines) if ln.startswith(b"=== ")), None
    )
    if mac_at is None:
        raise ValueError("missing header MAC line")
    stanzas: List[Stanza] = []
    i = 1
    while i < mac_at:
        line = lines[i]
        if not line:
            i += 1
            continue
        if not line.startswith(b"-> "):
            raise ValueError(f"expected arg-line, got {line[:40]!r}")
        fields = line[3:].split(b" ")
        if len(fields) != 2:
            raise ValueError(f"arg-line must carry exactly 2 fields, got {line[:60]!r}")
        wrapped_fk = _b64decode(fields[0], "wrapped file_key")
        c_x25519 = _b64decode(fields[1], "C_x25519")
        if len(wrapped_fk) != 32:
            raise ValueError("wrapped file_key must be 32B")
        if len(c_x25519) != kem_mod.X25519_LEN:
            raise ValueError(f"C_x25519 must be {kem_mod.X25519_LEN}B")
        c_mlkem: Optional[bytes] = None
        i += 1
        if i < mac_at:
            full = lines[i]
            if full.startswith(b"-> ") or full.startswith(b"=== "):
                # Classical-only stanza (no C_mlkem full-line)
                stanzas.append(
                    Stanza(wrapped_fk=wrapped_fk, c_x25519=c_x25519, c_mlkem=None)
                )
                continue
            if full:
                c_mlkem = _b64decode(full, "C_mlkem")
                if len(c_mlkem) != kem_mod.MLKEM_CT_LEN:
                    raise ValueError(f"C_mlkem must be {kem_mod.MLKEM_CT_LEN}B")
            i += 1
        stanzas.append(
            Stanza(wrapped_fk=wrapped_fk, c_x25519=c_x25519, c_mlkem=c_mlkem)
        )
    return stanzas


def parse_pfsh(data: bytes) -> Tuple[bytes, bytes, bytes]:
    """Split a file into (header, body, end). Binary body is never line-split."""
    if not data:
        raise ValueError("empty file")
    if not data.startswith(VERSION_LINE):
        raise ValueError("missing version line")
    if not data.endswith(END_MARKER):
        raise TruncatedFile("missing end marker")
    inner = data[: -len(END_MARKER)]
    lines = inner.split(b"\n")
    mac_at = next(
        (i for i, ln in enumerate(lines) if ln.startswith(b"=== ")), None
    )
    if mac_at is None:
        raise ValueError("missing header MAC line")
    header = b"\n".join(lines[: mac_at + 1]) + b"\n"
    body = inner[len(header) :]
    return header, body, END_MARKER


def _recover_file_key(
    header_body: bytes,
    stored_mac: bytes,
    stanzas: List[Stanza],
    keypair: KeyPair,
    require_pq: bool = True,
) -> Tuple[bytes, str]:
    """Open the first stanza that decrypts and passes the header MAC. Returns (file_key, mode).

    Hybrid stanzas are tried before classical-only ones. With require_pq, a classical-only stanza
    that would have opened for this key is never used: ClassicalOnlyRejected is raised instead.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    classical_would_open = False
    # A classical-only key has no ML-KEM secret: hybrid stanzas are not addressed to it.
    no_mlkem = kem_mod.is_all_zero(keypair.private[: kem_mod.MLKEM_SK_LEN])
    for stanza in sorted(stanzas, key=lambda st: st.c_mlkem is None):
        is_classical = stanza.c_mlkem is None
        if no_mlkem and not is_classical:
            continue
        try:
            if is_classical:
                k_hybrid = kem_mod.classical_only_decaps(keypair.private, stanza.c_x25519)
            else:
                # A genuine liboqs abort (MLKEMKeyCheckFailed) is loud and terminal.
                k_hybrid = kem_mod.hybrid_decaps(keypair.private, stanza.c_mlkem + stanza.c_x25519)
        except LowOrderX25519:
            continue
        wrap_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=b"", info=b"wrap"
        ).derive(k_hybrid)
        try:
            candidate = ChaCha20Poly1305(wrap_key).decrypt(
                WRAP_NONCE, stanza.wrapped_fk, b""
            )
        except Exception:
            continue
        if len(candidate) != 16:
            continue
        mac_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=b"", info=b"header"
        ).derive(candidate)
        expect = hmac_mod.new(mac_key, header_body, hashlib.sha256).digest()[:16]
        if not hmac_mod.compare_digest(expect, stored_mac):
            continue
        if is_classical and require_pq:
            classical_would_open = True
            continue
        return candidate, MODE_CLASSICAL if is_classical else MODE_HYBRID
    if classical_would_open:
        raise ClassicalOnlyRejected(
            "file is only readable through a classical-only (X25519) stanza; "
            "pass require_pq=False to accept that"
        )
    raise HeaderMACMismatch("no stanza decrypts under this key")


def _encrypt_with_file_key(
    plaintext: bytes,
    recipients: List[Recipient],
    file_key: bytes,
    classical_only: bool = False,
) -> bytes:
    """Private test hook: encrypt under a caller-chosen 16-byte file key.

    Reusing a file key across files reuses the keystream. Never expose this to callers.
    """
    from pqblocks_files.chunker import _chunk

    if not isinstance(plaintext, bytes):
        raise TypeError(f"plaintext must be bytes, got {type(plaintext).__name__}")
    if not isinstance(recipients, list):
        raise TypeError(f"recipients must be list, got {type(recipients).__name__}")
    if not recipients:
        raise ValueError("recipients must not be empty (grammar requires 1*recipient-stanza)")
    if len(file_key) != 16:
        raise ValueError(f"file_key must be 16 bytes, got {len(file_key)}")
    if not isinstance(classical_only, bool):
        raise TypeError(f"classical_only must be bool, got {type(classical_only).__name__}")

    header = _encode_header(recipients, file_key, classical_only=classical_only)
    body = b"".join(nonce + ct_tag for nonce, ct_tag in _chunk(plaintext, file_key))
    return header + body + END_MARKER


def encrypt(
    plaintext: bytes,
    recipients: List[Recipient],
    classical_only: bool = False,
) -> bytes:
    """Assemble a complete pfsh v1 file for the given recipients.

    A fresh random file key is used for every call. classical_only=True writes X25519-only
    stanzas (no post-quantum protection) and must be requested explicitly.
    """
    return _encrypt_with_file_key(plaintext, recipients, os.urandom(16), classical_only)


def decrypt(pfsh_bytes: bytes, keypair: KeyPair, require_pq: bool = True) -> bytes:
    """Recover the original plaintext. Loud errors only; never partial output.

    With require_pq=True (default) a file this key can only open through a classical-only
    stanza raises ClassicalOnlyRejected. Use decrypt_with_mode() to learn which mode was used.
    """
    return decrypt_with_mode(pfsh_bytes, keypair, require_pq).plaintext


def decrypt_with_mode(
    pfsh_bytes: bytes, keypair: KeyPair, require_pq: bool = True
) -> DecryptResult:
    """Like decrypt(), but returns DecryptResult(plaintext, mode) with mode in
    {MODE_HYBRID, MODE_CLASSICAL}."""
    if not isinstance(pfsh_bytes, (bytes, bytearray)):
        raise TypeError(f"pfsh_bytes must be bytes, got {type(pfsh_bytes).__name__}")
    if not isinstance(require_pq, bool):
        raise TypeError(f"require_pq must be bool, got {type(require_pq).__name__}")
    header, body, _end = parse_pfsh(bytes(pfsh_bytes))
    header_body, stored_mac = split_header_mac(header)
    try:
        stanzas = extract_stanza_fields(header)
    except ValueError as exc:
        raise HeaderMACMismatch(str(exc)) from exc
    file_key, mode = _recover_file_key(header_body, stored_mac, stanzas, keypair, require_pq)
    out = b""
    offset = 0
    expected_counter = 0
    saw_final = False
    while offset < len(body):
        if len(body) - offset < NONCE_LEN + TAG_LEN:
            raise TruncatedFile("short chunk frame")
        nonce, flag = read_chunk_nonce(body, offset)
        counter = int.from_bytes(nonce[:8], "big")
        if counter != expected_counter:
            raise NonMonotonicCounter(
                f"chunk counter {counter} out of order, want {expected_counter}"
            )
        is_final = flag == 0x01
        ct_len = min(len(body) - offset - NONCE_LEN - TAG_LEN, CHUNK_SIZE)
        if not is_final and ct_len != CHUNK_SIZE:
            raise TruncatedFile("short non-final chunk")
        payload_key = derive_payload_key(file_key, nonce)
        chunk_slice = body[offset + NONCE_LEN : offset + NONCE_LEN + ct_len + TAG_LEN]
        try:
            out += chacha20poly1305_decrypt(payload_key, nonce, chunk_slice)
        except TagVerificationFailed:
            if is_final:
                for alt_len in range(ct_len - 1, max(-1, ct_len - 1024), -1):
                    cand = body[offset + NONCE_LEN : offset + NONCE_LEN + alt_len + TAG_LEN]
                    try:
                        chacha20poly1305_decrypt(payload_key, nonce, cand)
                        raise TruncatedFile("trailing bytes after final chunk")
                    except TagVerificationFailed:
                        continue
            raise
        offset += NONCE_LEN + ct_len + TAG_LEN
        expected_counter += 1
        if is_final:
            if offset != len(body):
                raise TruncatedFile("trailing bytes after final chunk")
            saw_final = True
            break
    if not saw_final:
        raise TruncatedFile("no final chunk")
    return DecryptResult(plaintext=out, mode=mode)
