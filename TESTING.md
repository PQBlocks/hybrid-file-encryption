# Testing: pqblocks-files

This document details the test structure, coverage, execution procedures, and reproduction instructions for `pqblocks-files`.

## Test environment

- **Runner:** `pytest` 9.1.1 with `pytest-cov` 7.1.0 and `hypothesis` 6.168.0
- **Supported Python runtimes:** 3.11, 3.12, 3.13, 3.14
- **Native dependencies:** `liboqs.so.9` (liboqs 0.16.0 or 0.15.x) accessible via `OQS_LIB_PATH` or dynamic linker
- **Python dependencies:** `cryptography`, `bech32`

---

## Running the test suite

Set the library path pointing to your `liboqs.so.9` dynamic library before running:

```bash
cd packages/pqblocks-files
OQS_LIB_PATH=~/.local/lib/liboqs.so.9 LD_LIBRARY_PATH=~/.local/lib PYTHONPATH=src pytest -q
```

### With coverage report

```bash
cd packages/pqblocks-files
OQS_LIB_PATH=~/.local/lib/liboqs.so.9 LD_LIBRARY_PATH=~/.local/lib PYTHONPATH=src pytest --cov=pqblocks_files
```

---

## Test suite architecture

The test suite consists of **279 automated tests** across 13 test modules:

| Module | Test Count | Scope |
|---|---|---|
| `tests/test_aead.py` | 25 | ChaCha20-Poly1305 AEAD operations, key wrapping, nonce uniqueness |
| `tests/test_chunker.py` | 13 | 64 KiB chunk splitting, reassembly, tag verification, chunk counters |
| `tests/test_cli.py` | 20 | CLI subprocess invocations (`keygen`, `encrypt`, `decrypt`), `--passphrase-file`, exit codes (0, 1, 2, 4) |
| `tests/test_cli_direct.py` | 13 | In-process CLI entry points, argument error paths |
| `tests/test_coverage_extra.py` | 15 | Edge branch test coverage across encryption and decryption paths |
| `tests/test_encrypt.py` | 32 | Streaming hybrid file encryption, multi-recipient stanzas, corrupted payload rejection |
| `tests/test_fuzz_parsers.py` | 8 | Hypothesis property-based fuzzing of `parse_pfsh`, `extract_stanza_fields`, and header parsers |
| `tests/test_header.py` | 29 | PFSH format header serialization, truncated HMAC-SHA256, recipient lookup |
| `tests/test_kat_acvp.py` | 4 | NIST ACVP Known Answer Tests (KAT) for ML-KEM-768 |
| `tests/test_kat_wycheproof.py` | 5 | Project Wycheproof test vectors for X25519 and ChaCha20-Poly1305 |
| `tests/test_kem.py` | 17 | Hybrid ML-KEM-768 + X25519 key exchange, combiner, ctypes liboqs bindings |
| `tests/test_keys.py` | 11 | Key generation, scrypt passphrase derivation, Bech32 encoding, file permissions |
| `tests/test_security_fixes.py` | 87 | Regression tests for all crypto-review findings (passphrase handling, salt randomness, downgrade protection, size caps) |
| **Total** | **279** | **All passing** |

---

## Statement coverage breakdown

Measured on Python 3.14.8 with `pytest-cov`:

| Module | Statements | Missed | Coverage |
|---|---|---|---|
| `src/pqblocks_files/__init__.py` | 0 | 0 | 100% |
| `src/pqblocks_files/ae.py` | 37 | 0 | 100% |
| `src/pqblocks_files/chunker.py` | 49 | 5 | 90% |
| `src/pqblocks_files/cli.py` | 160 | 30 | 81% |
| `src/pqblocks_files/encrypt.py` | 206 | 13 | 94% |
| `src/pqblocks_files/header.py` | 182 | 17 | 91% |
| `src/pqblocks_files/kem.py` | 161 | 14 | 91% |
| `src/pqblocks_files/keys.py` | 160 | 15 | 91% |
| `src/pqblocks_files/pqtypes.py` | 21 | 0 | 100% |
| **Total** | **976** | **94** | **90%** |

---

## Standalone examples verification

Two runnable example scripts in `examples/` demonstrate standard workflows:

```bash
# 1. Quickstart file roundtrip (encrypt and decrypt)
OQS_LIB_PATH=~/.local/lib/liboqs.so.9 LD_LIBRARY_PATH=~/.local/lib PYTHONPATH=src python3 examples/quickstart.py

# 2. Key files on disk, passphrase prompts, and downgrade rejection
OQS_LIB_PATH=~/.local/lib/liboqs.so.9 LD_LIBRARY_PATH=~/.local/lib PYTHONPATH=src python3 examples/key_files_and_policy.py
```
