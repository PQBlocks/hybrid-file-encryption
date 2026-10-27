# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-25

### Pre-publish fixes
- `chunker.chunk`, `header.encode_header` and the `eph_x25519_sk` parameter of `hybrid_encap` / `classical_only_encap` are private (`_chunk`, `_encode_header`, `_eph_x25519_sk`): they let a caller choose or reuse a file key / ephemeral key. README no longer presents them as building blocks.
- Dependency bounds: `cryptography>=42,<51`, `bech32>=1.2,<2` (lower bounds verified with the suite on cryptography 42.0.0 / bech32 1.2.0; installed 50.0.2 / 1.2.0).
- A classical-only key now skips hybrid stanzas, so its holder gets `HeaderMACMismatch` ("no stanza decrypts") instead of an ML-KEM key-check abort.
- Tests: `TestNoPublicFileKeyReuseHelpers` (2 tests).

### Added
- Hybrid file encryption with ML-KEM-768 (liboqs) and X25519 (pyca/cryptography); chunked ChaCha20-Poly1305 payload in the `pfsh` v1 format; multiple recipients.
- Command line `pqblocks-files keygen | encrypt | decrypt`.
- Versioned key-file formats (public: Bech32 `pfsh1pq` with version and algorithm id; private: `PFSK` v1, scrypt n=2^17 r=8 p=1, random 16-byte salt per file, ChaCha20-Poly1305 with the header as associated data). Private keys are created `0600` with `O_EXCL` and never overwritten.
- Private-key passphrase from a prompt (`getpass`, confirmed on keygen) or `--passphrase-file`; empty passphrases refused; no default passphrase; never printed.
- `decrypt(..., require_pq=True)` by default, `ClassicalOnlyRejected`, `decrypt_with_mode()` returning the mode used, CLI `--allow-classical` and exit code 4.
- liboqs binding checks `OQS_version()` (0.15.x and 0.16.x accepted) and verifies ML-KEM-768 buffer sizes with raised exceptions, not `assert`.
- `hybrid_encap` rejects an all-zero ML-KEM public key.
- Tests: official Wycheproof and ACVP ML-KEM-768 vectors, hypothesis fuzzing of the parsers, regression tests for each review finding.
- Examples and a library-level timing script.

### Changed (review fixes, recorded because tests that asserted the old behaviour were updated)
- `encrypt()` no longer accepts a caller-supplied `file_key`, and the CLI has no `--file-key`; tests use the private `_encrypt_with_file_key` hook. Tests that pinned a file key now go through it.
- Tests that decrypted classical-only files now pass `require_pq=False` (CLI tests pass `--allow-classical`); the CLI test for `--file-key` now expects the option to be rejected (argparse exit 2).
- CLI tests pass `--passphrase-file`; the old built-in default passphrase is gone.
- `KeyPair.private` is hidden from `repr`; `unchunk` is private (`_unchunk`); a low-order X25519 point in one stanza no longer aborts the search through the other stanzas; the public-key loader requires the exact decoded length and zero padding bits.
- The reference implementation used by the equivalence tests moved from the installed package into `tests/`, because it accepts a caller-chosen file key.
- Corrected docstrings: the derived passphrase key is 32 bytes, not "32-bit"; the KEM is ML-KEM-768 throughout.
