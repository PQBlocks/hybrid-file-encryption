# Verification report: pqblocks-files 0.1.0

This is an internal self-verification report detailing test execution, packaging checks, and security review remediations for `pqblocks-files` 0.1.0. This is not an external audit or third-party validation.

## Summary

| Area | Result |
|---|---|
| Correctness | 279 / 279 automated tests pass across Python 3.11, 3.12, 3.13, 3.14 |
| Coverage | 90% statement coverage (976 statements, 94 missed) |
| Installation | Clean wheel installation with dependencies on Python 3.11, 3.12, 3.13, 3.14 |
| Examples | All 2 standalone example scripts pass cleanly across Python 3.11, 3.12, 3.13, 3.14 |
| Packaging | Source distribution and wheel build cleanly; `twine check --strict` passes |
| Native dependency | Requires `liboqs.so.9` (liboqs 0.16.0 or 0.15.x) |
| Review status | All 1 CRITICAL and 6 HIGH findings from the initial integration review were resolved test-first (85 regression tests). Three MEDIUM findings are disclosed in [SECURITY_NOTES.md](SECURITY_NOTES.md). |

---

## Review checks completed

| Check | Purpose | Result |
|---|---|---|
| Check 1 (design review) | Scope, sources, and algorithm parameters identified | Pass |
| Check 2 (spec review) | PFSH v1 chunk envelope, header MAC, and key format specified | Pass |
| Check 3 (correctness) | Full suite of 279 tests, including 87 security remediation tests; 90% coverage | Pass |
| Check 4 (benchmark review) | Streaming throughput over 10 KiB to 10 MiB payloads ([BENCHMARKS.md](BENCHMARKS.md)) | Pass |
| Check 5 (adversarial review) | Fuzzing parsers via Hypothesis (400 examples/property), corrupted ciphertext tests | Pass |
| Release check | Wheel build, clean venv installation, 4 Python versions, 0 leak hits | Pass |

---

## Remediated defects from crypto review

Prior to this release, an integration review identified 1 CRITICAL and 6 HIGH defects. All 7 defects were remediated test-first and validated by regression tests in `tests/test_security_fixes.py`:

1. **Hard-coded default passphrase removed (CRITICAL):**
   - *Previous behavior:* The CLI encrypted private keys using a hardcoded public default passphrase.
   - *Remediation:* Replaced with interactive prompt (`getpass`) or `--passphrase-file`. Empty passphrases are refused. The passphrase is never printed to logs or stdout.
2. **Key-file password derivation hardened (HIGH):**
   - *Previous behavior:* Fixed global salt with PBKDF2.
   - *Remediation:* Random 16-byte salt per key file using scrypt ($N = 2^{17}, r = 8, p = 1$) under format version 1 (`PFSK` magic).
3. **Keystream reuse via caller file-key eliminated (HIGH):**
   - *Previous behavior:* Caller-supplied `file_key` in public `encrypt()` and CLI `--file-key` allowed keystream reuse across multiple files.
   - *Remediation:* Removed `file_key` from public `encrypt()` and dropped `--file-key` from the CLI. All file keys are generated via `os.urandom(16)`.
4. **Classical downgrade protection enforced (HIGH):**
   - *Previous behavior:* Hybrid keypairs silently decrypted classical-only files without alerting the caller.
   - *Remediation:* Added `require_pq=True` default in library and CLI. Files containing only classical (X25519) stanzas are rejected unless explicitly allowed via `--allow-classical`.
5. **Key format algorithm identification (HIGH):**
   - *Previous behavior:* Classical keys were represented on disk with zeroed ML-KEM fields and no algorithm ID.
   - *Remediation:* Distinct algorithm identifiers (`ALG_HYBRID = 1`, `ALG_X25519_ONLY = 2`) encoded in public Bech32 strings and private key envelopes. Hybrid encapsulation rejects all-zero public keys.
6. **liboqs ctypes binding safety hardened (HIGH):**
   - *Previous behavior:* Size checks used `assert` (stripped under `python -O`), and `OQS_version()` was not validated.
   - *Remediation:* Pinned soname check, runtime `OQS_version()` verification, and explicit `RuntimeError` raises instead of asserts.
7. **Parser fuzzing & corrupted ciphertext assertions (HIGH):**
   - *Previous behavior:* Untested parser boundaries and vague error assertions.
   - *Remediation:* Added Hypothesis property-based fuzz tests in `tests/test_fuzz_parsers.py` (400 examples per property) and strict exception type assertions.

---

## Verification test evidence

```
build sdist+wheel                  PASS  Successfully built dist/pqblocks_files-0.1.0-py3-none-any.whl
twine check --strict               PASS  Checking dist/*: PASSED
python 3.11: tests                 PASS  279 passed
python 3.12: tests                 PASS  279 passed
python 3.13: tests                 PASS  279 passed
python 3.14: tests                 PASS  279 passed
examples (quickstart, key_files_and_policy) PASS on all four versions
leak gate (folder + wheel + sdist) PASS  0 leak hits
```
