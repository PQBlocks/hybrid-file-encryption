# pqblocks-files

Hybrid post-quantum file encryption for Python and the command line: ML-KEM-768 plus X25519 key encapsulation, with the payload sealed in 64 KiB ChaCha20-Poly1305 chunks (the `pfsh` v1 file format).
Use it to encrypt files or byte strings to one or more recipients' public keys so that a future quantum computer, or a break of either primitive alone, does not expose them.
Implements NIST FIPS 203 (ML-KEM-768, via liboqs), RFC 7748 (X25519), RFC 8439 (ChaCha20-Poly1305) and RFC 5869 (HKDF). **Not FIPS or CMVP validated. Pre-1.0: not independently audited.**

```bash
pip install pqblocks-files        # needs a system liboqs 0.15.x or 0.16.x, see Requirements
```

```python
from pqblocks_files.encrypt import encrypt, decrypt
from pqblocks_files.keys import keygen

keypair = keygen()                                    # ML-KEM-768 + X25519
blob = encrypt(b"quarterly numbers", [keypair.public])  # fresh random file key every call
assert decrypt(blob, keypair) == b"quarterly numbers"   # refuses classical-only files by default
```

## Requirements

- Python 3.11 or newer; `cryptography` and `bech32` (installed by pip).
- **A shared liboqs** (`liboqs.so`, version 0.15.x or 0.16.x) found by the system loader, or pointed to with `OQS_LIB_PATH=/path/to/liboqs.so.9`. Any other liboqs version is refused at import with a `RuntimeError`. pip does not install liboqs. This was verified against liboqs 0.16.0; the CI workflow builds 0.15.0.

## Why PQBlocks

- **Hybrid by default:** every file key is wrapped under ML-KEM-768 *and* X25519. Classical-only files are a loud, explicit opt-in on both write (`classical_only=True`) and read (`require_pq=False`).
- **No foot-guns in the API:** no nonce, file-key or algorithm parameters. The file key is always fresh from the OS CSPRNG.
- **Private keys are passphrase-protected properly:** scrypt (n=2^17, r=8, p=1), a random 16-byte salt per file, versioned format, created `0600` with `O_EXCL`. The CLI has no default passphrase.
- **Tested against hostile input:** 279 tests including Wycheproof and ACVP ML-KEM-768 vectors, and property-based fuzzing of the parsers. See [TESTING.md](TESTING.md).
- **Honest limits:** see Limitations and [SECURITY_NOTES.md](SECURITY_NOTES.md). The open medium-severity items are listed there.
- **Licence:** Apache-2.0.

## Usage

### Library

```python
from pqblocks_files.keys import keygen, save_public_key, save_private_key, load_public_key, load_private_key
from pqblocks_files.encrypt import encrypt, decrypt, decrypt_with_mode
from pqblocks_files.pqtypes import KeyPair

kp = keygen()
save_public_key(kp, "alice.pub")                       # Bech32 text, mode 0444
save_private_key(kp, "alice.key", b"a long passphrase")  # scrypt + ChaCha20-Poly1305, mode 0600, never overwrites

alice = KeyPair(public=load_public_key("alice.pub"), private=load_private_key("alice.key", b"a long passphrase"))
blob = encrypt(open("report.pdf", "rb").read(), [alice.public])
result = decrypt_with_mode(blob, alice)                # result.plaintext, result.mode == "hybrid"
```

`encrypt` takes a list of recipients; any one of their private keys opens the file.

### Command line

```bash
pqblocks-files keygen --output alice.pub --output-sec alice.key      # prompts for a passphrase (twice)
pqblocks-files encrypt --recipient alice.pub --output report.pfsh report.pdf
pqblocks-files decrypt --key alice.key --output report.pdf report.pfsh   # prompts for the passphrase
```

For scripts use `--passphrase-file FILE` (one trailing newline is stripped; an empty passphrase is refused). The passphrase is never accepted as an argument, never has a default, and is never printed.

Exit codes: 0 success; 1 bad input or malformed file; 2 key not found in header or key file could not be unlocked; 3 ML-KEM key-check abort; 4 classical-only file refused (re-run with `--allow-classical`).

### Downgrade policy

`decrypt()` has `require_pq=True` by default. A file that your key can open only through a classical-only (X25519) stanza raises `ClassicalOnlyRejected` instead of being read. Pass `require_pq=False` (CLI: `--allow-classical`) to accept it; `decrypt_with_mode()` tells you which mode opened the file.

## API reference

`encrypt(plaintext: bytes, recipients: list[Recipient], classical_only: bool = False) -> bytes`
Complete `pfsh` v1 file. `classical_only=True` writes X25519-only stanzas (no post-quantum protection). Raises `ValueError` for no recipients or an all-zero ML-KEM key (a classical-only key used without `classical_only=True`), `TypeError` for wrong argument types.

`decrypt(pfsh_bytes: bytes, keypair: KeyPair, require_pq: bool = True) -> bytes`
Plaintext, or an exception; never partial output. Exceptions: `HeaderMACMismatch` (no stanza opens under this key, or the header is malformed), `ClassicalOnlyRejected`, `TruncatedFile`, `TagVerificationFailed`, `NonMonotonicCounter`, `MLKEMKeyCheckFailed`, `ValueError`.

`decrypt_with_mode(pfsh_bytes, keypair, require_pq=True) -> DecryptResult`
`DecryptResult(plaintext, mode)`, `mode` is `"hybrid"` or `"classical"` (`MODE_HYBRID`, `MODE_CLASSICAL` in `pqblocks_files.encrypt`). `plaintext` is hidden from `repr`.

`keygen(classical_only: bool = False) -> KeyPair`; `KeyPair(public: Recipient, private: bytes)` (private is hidden from `repr`); `Recipient(hybrid_pk: bytes, label: str = "")`.

`save_public_key(keypair, path)`, `load_public_key(path) -> Recipient`, `save_private_key(keypair, path, passphrase: bytes)`, `load_private_key(path, passphrase: bytes) -> bytes`. Loaders raise `ValueError` on any malformed, truncated, tampered or unknown-version file, and on an empty passphrase.

`parse_header` and the framing helpers in `pqblocks_files.encrypt` are internal and may change. Helpers that take a caller-chosen file key or ephemeral key (`_chunk`, `_encode_header`, the `_eph_x25519_sk` parameters in `kem`) are private on purpose: reusing a key would reuse a keystream.

## Limitations

- **Whole file in memory:** `encrypt` and `decrypt` take and return `bytes`; there is no streaming API.
- **Decrypt is slower than encrypt:** at 10 MB the library-level median was 0.18 s to decrypt against 0.02 s to encrypt (see [BENCHMARKS.md](BENCHMARKS.md)). The cause was not profiled.
- **No sender authentication or signatures:** anyone who has your public key can create a file for you. Use a signature scheme on top if you need provenance.
- **No zeroization** of keys or plaintext (Python `bytes` are immutable); see [SECURITY_NOTES.md](SECURITY_NOTES.md).
- **Pre-1.0 format and API:** the key-file format is versioned (v1) but may change before 1.0. Key files from earlier unreleased builds are refused.
- **Key distribution is out of scope:** nothing authenticates a public key file to a person.
- **Open medium-severity design items** (combiner does not bind the X25519 ciphertext and public keys; shared HKDF label in classical mode; 128-bit file key) are listed in [SECURITY_NOTES.md](SECURITY_NOTES.md).

## Security notes

See [SECURITY_NOTES.md](SECURITY_NOTES.md) and [SECURITY.md](SECURITY.md). Not independently audited; not FIPS 140-3 or CMVP validated.

## Verification

[TESTING.md](TESTING.md) · [BENCHMARKS.md](BENCHMARKS.md) · [EVIDENCE.md](EVIDENCE.md) · [VERIFICATION_REPORT.md](VERIFICATION_REPORT.md) · [USE_CASES.md](USE_CASES.md) · [AGENTS.md](AGENTS.md)

## Part of PQBlocks

[PQBlocks](https://github.com/PQBlocks) builds open, tested building blocks for the post-quantum transition. This package is its hybrid file-encryption tool.
