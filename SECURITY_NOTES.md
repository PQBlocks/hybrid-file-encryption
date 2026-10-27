# Security notes: pqblocks-files

Status: pre-1.0 (0.1.0). Checked by its own test suite and an internal cryptographic integration review (see [VERIFICATION_REPORT.md](VERIFICATION_REPORT.md)). **No external third-party audit. Not FIPS 140-3 or CMVP validated.** A re-review of the fixes is pending; do not treat this release as publication-ready.

## What it protects

- Confidentiality and integrity of file contents against anyone who does not hold a recipient private key, including an adversary with a quantum computer that breaks X25519, or one that breaks ML-KEM-768 alone: the file key is wrapped under a key derived from both shared secrets.
- Integrity of the header (16-byte truncated HMAC-SHA256 keyed from the file key), of each 64 KiB chunk (Poly1305 tag), of chunk order, and of the final-chunk marker (flag in the nonce). Truncation, reordering, a dropped final chunk and trailing bytes are rejected; no partial plaintext is returned.
- Private-key files at rest, against offline guessing: scrypt n=2^17, r=8, p=1 with a random 16-byte salt per file, ChaCha20-Poly1305 with the format header as associated data. Strength depends on the passphrase; no strength check is made.

## What it does not protect

- **Sender authentication / signatures:** none. Anyone with a public key can produce a valid file.
- **Metadata:** the number of recipients, file size (to chunk granularity plus a fixed overhead) and the format are visible. There is no padding and no recipient hiding.
- **Public-key authenticity:** nothing binds a public key file to a person. Verify keys out of band.
- **Memory:** see Zeroization.
- **Classical-only mode** (`classical_only=True`, `--classical`) has no post-quantum protection. It is opt-in on write and on read.

## Backends

| Function | Library |
|---|---|
| ML-KEM-768 | liboqs, through a hand-written `ctypes` binding (`kem.py`) |
| X25519, HKDF-SHA256, HMAC, ChaCha20-Poly1305, scrypt | pyca/cryptography |
| Bech32 | `bech32` package |

No primitive is implemented in this package. The liboqs binding checks the library version at import (`OQS_version()`; 0.15.x and 0.16.x are accepted, anything else raises `RuntimeError`), verifies the ML-KEM-768 buffer sizes against the constants, checks every return code and every input length before a call, and uses no `assert` for checks (so `python -O` behaves the same). It was verified against liboqs 0.16.0; 0.15.x is accepted by the version check but is not covered by a local run here.

## Constant-time status

Not claimed for this package. ML-KEM and X25519 timing behaviour is whatever liboqs and OpenSSL (via pyca) provide. The header MAC is compared with `hmac.compare_digest`. Python-level code around the primitives (parsing, slicing, `bytes` handling) is not constant time. The all-zero checks on key material use `hmac.compare_digest`.

## Zeroization

**None.** Private keys, file keys, shared secrets, derived keys, passphrases and plaintexts are held in immutable Python `bytes` objects (and `str` for prompted passphrases) that are never overwritten and may be copied by the interpreter, the allocator or swap. Use full-disk encryption and disable core dumps and swap for high-value keys. ctypes buffers used with liboqs are not wiped either.

## Randomness

`os.urandom` (file key, salts, nonces), pyca/cryptography (ephemeral X25519 keys) and liboqs (ML-KEM key generation and encapsulation, using liboqs's own RNG, which was not inspected for this release). There is no caller-seedable randomness in the public API: no nonce, file-key or seed parameters.

## Input handling

- Parsers (`parse_pfsh`, `extract_stanza_fields`, `parse_header`, key-file loaders) raise documented exceptions on hostile input. They are fuzzed with hypothesis (400 examples per property, `tests/test_fuzz_parsers.py`); a mutated file either fails loudly or decrypts to exactly the original.
- Key files are read with a 1 MiB cap; structure (magic, version, algorithm id, exact length) is validated *before* the expensive KDF.
- `decrypt` reads the whole file into memory; a caller handling untrusted files should cap their size.
- Secrets are not placed in `repr` of `KeyPair` or `DecryptResult`, and are not included in exception messages. The CLI never prints the passphrase.

## Key files

- Private key: `-----BEGIN PFSH PRIVATE KEY-----` PEM-like text; payload `"PFSK" | version | algorithm id | salt(16) | nonce(12) | ciphertext | tag`. Unknown versions or algorithm ids are rejected. The scrypt parameters are fixed by format version 1.
- Public key: Bech32 with HRP `pfsh1pq`; payload `version | algorithm id | key`. X25519-only keys are stored as 32 bytes with their own algorithm id; `hybrid_encap` additionally rejects an all-zero ML-KEM key.
- Files are created with `O_CREAT | O_EXCL` and the final mode (`0600` private, `0444` public) and are never overwritten. Permission bits are POSIX; on other platforms they are advisory.
- The CLI passphrase comes from `getpass` or `--passphrase-file`. The passphrase file's own permissions are not checked.

## Dependencies

Runtime: `cryptography`, `bech32`, and a system liboqs. Tests: `pytest`, `hypothesis`. A dependency vulnerability scan was not run for this release (not measured).

## Known open items (not fixed in 0.1.0)

Each was found in the internal review and is deliberately left, for the reason given.

| Severity | Item | Why open / planned fix |
|---|---|---|
| MEDIUM | **Combiner does not bind the X25519 ciphertext or the public keys.** `K = HKDF(ss_mlkem \|\| ss_x25519, info="pfsh-hybrid")`. The hybrid's CCA security then rests on ML-KEM alone; if ML-KEM were broken, the X25519 half would not add the binding that an X-Wing style combiner (`SHA3-256(label \| ss_M \| ss_X \| ct_X \| pk_X)`) provides. | Changing it alters the derivation inputs, which this release does not do. Fix before 1.0 with a new format version. |
| MEDIUM | **Classical-only mode reuses the HKDF info `pfsh-hybrid`**; the two modes differ only in input length. | Same: new label (for example `pfsh-classical`) needs a format version bump. |
| MEDIUM (design) | **The file key is 16 bytes (128 bits).** Against a quantum adversary running Grover's algorithm, the payload keys derived from it offer roughly 64 bits of generic search cost. This is an observation of the design, not a measured attack. | Needs a format change (32-byte file key). Plan before 1.0. |
| LOW | On a tag failure in the final chunk, `decrypt` retries the final chunk at up to ~1023 shorter lengths to report "trailing bytes". Extra work and a distinguishable error, bounded and with no plaintext released. | Removing it changes which exception some corrupted files raise; left for 0.2. |
| LOW | A classical-only key is represented in memory as a hybrid key with zero-filled ML-KEM parts (on disk it has its own algorithm id). | In-memory layout kept for API stability; guarded by the all-zero checks. |
| LOW | The Bech32 checksum's error-detection guarantee is defined up to 90 characters; public key files are about 1.9 kB. Random corruption is still caught with probability 1 - 2^-30, and the exact length and zero-padding checks apply. | Consider an explicit fingerprint or checksum line. |
| LOW | Decrypt is much slower than encrypt for large files (cause not profiled). | Performance, not security. |

## Audit status

Internal review only. Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
