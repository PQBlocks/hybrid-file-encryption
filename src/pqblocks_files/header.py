"""Header parser/generator for the pfsh v1 format.

Contract:
  _encode_header(recipients, file_key, classical_only=False) -> header: bytes
  parse_header(header, candidates) -> List[Recipient]

Grammar:
  version-line = "pfsh-encryption.org/v1" LF
  recipient-stanza = arg-line *full-line LF
  arg-line = "-> " base64(wrapped_file_key: 32B) SP base64(C_x25519: 32B) LF
  full-line = base64(C_mlkem: 1088B) LF
  header-mac-line = "=== " BASE64(header_mac: 16B) LF

classical_only=True: stanza has NO full-line.
classical_only=False: stanza has arg-line + one full-line.

header_body = all bytes from after version-line LF up to but not including header-mac-line
header_mac = HMAC-SHA256(header_mac_key, header_body)[:16]
header_mac_key = HKDF-SHA256(ikm=file_key, salt=b"", info=b"header")
wrapped_file_key = ChaCha20Poly1305(wrap_key).encrypt(wrap_nonce, file_key, aad=b"")
wrap_key = HKDF-SHA256(ikm=K_hybrid, salt=b"", info=b"wrap")
wrap_nonce = bytes(11) + b"\x00"

Headers are randomised: ML-KEM encapsulation and the ephemeral X25519 keys are fresh for every
stanza, so two headers for the same file_key differ.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as hmac_mod
from typing import List, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pqblocks_files.kem import (
    MLKEM_CT_LEN,
    MLKEM_PK_LEN,
    MLKEM_SK_LEN,
    X25519_LEN,
    classical_only_decaps,
    classical_only_encap,
    hybrid_decaps,
    hybrid_encap,
)
from pqblocks_files.pqtypes import (
    HeaderMACMismatch,
    KeyPair,
    LowOrderX25519,
    MLKEMKeyCheckFailed,
    Recipient,
)

_VERSION = b"pfsh-encryption.org/v1\n"
_WRAP_NONCE = bytes(11) + b"\x00"
_HKDF_INFO_WRAP = b"wrap"
_HKDF_INFO_HEADER = b"header"
_MAC_BYTES = 16


def _b64(data: bytes) -> bytes:
    """Base64-encode data with no newlines."""
    return base64.b64encode(data)


def _unb64(s: bytes) -> bytes:
    """Base64-decode, stripping any whitespace/newlines."""
    s = s.strip()
    # Remove newlines for multi-line base64
    s = s.replace(b"\n", b"").replace(b" ", b"")
    return base64.b64decode(s, validate=True)


def _derive_header_mac_key(file_key: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",
        info=_HKDF_INFO_HEADER,
    )
    return hkdf.derive(file_key)


def _derive_wrap_key(k_hybrid: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",
        info=_HKDF_INFO_WRAP,
    )
    return hkdf.derive(k_hybrid)


def _compute_mac(file_key: bytes, header_body: bytes) -> bytes:
    mac_key = _derive_header_mac_key(file_key)
    return hmac_mod.new(mac_key, header_body, hashlib.sha256).digest()[:_MAC_BYTES]


def _empty_recipients_mac_line(file_key: bytes) -> bytes:
    """MAC line for empty recipients (MAC computed over just version line)."""
    header_body = _VERSION
    mac = _compute_mac(file_key, header_body)
    return b"=== " + _b64(mac) + b"\n"


def _encode_header(
    recipients: List[Recipient],
    file_key: bytes,
    classical_only: bool = False,
) -> bytes:
    """Build a pfsh v1 header for the given recipients and file_key.

    For classical_only=True, each stanza contains only the arg-line with
    2 fields (wrapped_fk, C_x25519) and no full-line.

    For classical_only=False (hybrid), each stanza contains:
      - arg-line: "-> " base64(wrapped_fk) SP base64(C_x25519) LF
      - full-line: base64(C_mlkem) LF
    """
    if len(file_key) != 16:
        raise ValueError(f"file_key must be 16 bytes, got {len(file_key)}")

    # Empty recipients: just version + MAC (computed over version line)
    if not recipients:
        return _VERSION + _empty_recipients_mac_line(file_key)

    stanzas: List[bytes] = []
    for rec in recipients:
        if classical_only:
            # X25519-only encapsulation: derive K from X25519 shared secret alone,
            # so the header can be decoded via classical_only_decaps path.
            x25519_pk = rec.hybrid_pk[MLKEM_PK_LEN:]  # last 32B of hybrid_pk
            c_x25519, k = classical_only_encap(x25519_pk)
            wrap_key = _derive_wrap_key(k)
            cpaead = ChaCha20Poly1305(wrap_key)
            wrapped_fk = cpaead.encrypt(_WRAP_NONCE, file_key, b"")
            stanza = b"-> " + _b64(wrapped_fk) + b" " + _b64(c_x25519) + b"\n"
        else:
            # Full hybrid encapsulation: K = HKDF(K_mlkem || K_x25519)
            c_hybrid, k_hybrid = hybrid_encap(rec.hybrid_pk)
            wrap_key = _derive_wrap_key(k_hybrid)
            cpaead = ChaCha20Poly1305(wrap_key)
            wrapped_fk = cpaead.encrypt(_WRAP_NONCE, file_key, b"")
            c_mlkem = c_hybrid[:MLKEM_CT_LEN]
            c_x25519 = c_hybrid[MLKEM_CT_LEN:]
            arg_line = b"-> " + _b64(wrapped_fk) + b" " + _b64(c_x25519) + b"\n"
            full_line = _b64(c_mlkem) + b"\n"
            stanza = arg_line + full_line

        stanzas.append(stanza)

    header_body = _VERSION + b"".join(stanzas)
    mac = _compute_mac(file_key, header_body)
    header = header_body + b"=== " + _b64(mac) + b"\n"
    return header


def _parse_stanzas(lines: List[bytes], mac_line_idx: int) -> List[dict]:
    """Parse stanzas from lines between version line and MAC line.

    Returns list of stanza dicts with keys:
      wrapped_fk, c_x25519, c_mlkem (None for classical), is_classical
    """
    stanzas: List[dict] = []
    i = 1  # skip version line
    while i < mac_line_idx:
        line = lines[i]

        # Skip empty lines
        if not line:
            i += 1
            continue

        if not line.startswith(b"-> "):
            raise ValueError(f"expected arg-line, got: {line[:40]!r}")

        # Parse arg-line
        arg_data = line[3:]
        parts = arg_data.split(b" ")
        if len(parts) != 2:
            raise ValueError(
                f"arg-line must have exactly 2 space-separated fields, got {len(parts)}: {line[:60]!r}"
            )

        try:
            wrapped_fk = _unb64(parts[0])
            c_x25519 = _unb64(parts[1])
        except Exception as exc:
            raise ValueError(f"invalid base64 in arg-line: {exc}") from exc

        if len(wrapped_fk) != 32:
            raise ValueError(f"wrapped_file_key must be 32B, got {len(wrapped_fk)}")
        if len(c_x25519) != 32:
            raise ValueError(f"C_x25519 must be 32B, got {len(c_x25519)}")

        # Check if next non-empty line is a full-line (C_mlkem for hybrid)
        is_classical = True
        c_mlkem: Optional[bytes] = None
        i += 1
        if i < mac_line_idx:
            next_line = lines[i]
            if next_line:  # non-empty line follows
                if next_line.startswith(b"-> "):
                    pass
                elif next_line.startswith(b"=== "):
                    raise ValueError(
                        "unexpected MAC line inside stanza"
                    )
                else:
                    try:
                        c_mlkem = _unb64(next_line)
                    except Exception as exc:
                        raise ValueError(
                            f"malformed full-line: invalid base64 in full-line: {exc}"
                        ) from exc
                    if len(c_mlkem) != MLKEM_CT_LEN:
                        raise ValueError(
                            f"C_mlkem must be {MLKEM_CT_LEN}B, got {len(c_mlkem)}"
                        )
                    is_classical = False
                    i += 1

        stanzas.append({
            "wrapped_fk": wrapped_fk,
            "c_x25519": c_x25519,
            "c_mlkem": c_mlkem,
            "is_classical": is_classical,
        })

    return stanzas


def parse_header(
    header: bytes,
    candidates: List[KeyPair],
) -> List[Recipient]:
    """Parse a pfsh v1 header and return matching recipients.

    Raises HeaderMACMismatch if no candidate matches.
    Raises ValueError for malformed headers.
    """
    if not header:
        raise ValueError("empty header")
    if not header.startswith(_VERSION):
        raise ValueError("missing version line")

    lines = header.split(b"\n")
    if lines and lines[-1] == b"":
        lines = lines[:-1]

    mac_line_idx = None
    for i, line in enumerate(lines):
        if line.startswith(b"=== "):
            mac_line_idx = i
    if mac_line_idx is None:
        raise ValueError("missing header MAC line")

    # Decode and validate MAC
    mac_b64 = lines[mac_line_idx][4:]
    try:
        mac = _unb64(mac_b64)
    except Exception:
        raise ValueError("invalid MAC base64")
    if len(mac) != _MAC_BYTES:
        raise ValueError(f"MAC must be {_MAC_BYTES}B, got {len(mac)}")

    # header_body: all lines before the MAC line (with trailing LF)
    header_body = b"\n".join(lines[:mac_line_idx]) + b"\n"

    body_lines = lines[1:mac_line_idx]  # skip version line

    # Validate all body lines are well-formed BEFORE checking stanza count.
    # This catches "not-a-stanza" type errors (e.g. random text between version
    # and MAC) as ValueError rather than masking them under HeaderMACMismatch.
    for line in body_lines:
        if not line:
            continue
        if line.startswith(b"-> "):
            continue
        if line.startswith(b"=== "):
            raise ValueError("unexpected MAC line inside stanza")
        # Must be a full-line: base64 of C_mlkem
        try:
            _unb64(line)
        except Exception as exc:
            raise ValueError(
                f"malformed full-line: invalid base64 in full-line: {exc}"
            ) from exc

    num_stanzas = sum(1 for l in body_lines if l.startswith(b"-> "))

    # No stanzas: empty recipients case
    if num_stanzas == 0:
        if not candidates:
            return []
        # No stanzas but candidates provided - no key to match
        raise HeaderMACMismatch("empty recipients header with no matching key")

    # Parse stanzas
    stanzas = _parse_stanzas(lines, mac_line_idx)

    # Try each candidate
    matched_recipients: List[Recipient] = []
    for kp in candidates:
        for stanza in stanzas:
            c_x25519 = stanza["c_x25519"]
            if stanza["is_classical"]:
                try:
                    k_hybrid = classical_only_decaps(kp.private, c_x25519)
                except Exception:
                    continue
            else:
                c_mlkem = stanza["c_mlkem"]
                if c_mlkem is None:
                    continue
                c_hybrid = c_mlkem + c_x25519
                try:
                    k_hybrid = hybrid_decaps(kp.private, c_hybrid)
                except (MLKEMKeyCheckFailed, LowOrderX25519):
                    continue

            wrap_key = _derive_wrap_key(k_hybrid)
            cpaead = ChaCha20Poly1305(wrap_key)
            try:
                file_key_candidate = cpaead.decrypt(_WRAP_NONCE, stanza["wrapped_fk"], b"")
            except Exception:
                continue
            if len(file_key_candidate) != 16:
                continue

            expected_mac = _compute_mac(file_key_candidate, header_body)
            if not hmac_mod.compare_digest(expected_mac, mac):
                continue

            if kp.public not in matched_recipients:
                matched_recipients.append(kp.public)
            break

    if not matched_recipients:
        # HeaderMACMismatch is raised only after the header structure has been
        # validated, i.e. when a MAC/decryption mismatch is the specific cause.
        # For "no stanzas" or "malformed body" cases, raise ValueError.
        if num_stanzas == 0:
            raise HeaderMACMismatch("no recipients in header")
        raise HeaderMACMismatch("no matching recipient found in header")
    return matched_recipients
