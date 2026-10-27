# Evidence: pqblocks-files

Where each part of the implementation comes from, and how the code maps to the published methods. Where a description and the code disagree, the code is authoritative.

## Primary sources

1. NIST. *FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard.* 2024-08-13. doi:[10.6028/NIST.FIPS.203](https://doi.org/10.6028/NIST.FIPS.203) (DOI confirmed through the Crossref API). Defines ML-KEM-768 including implicit rejection on decapsulation failure.
2. A. Langley, M. Hamburg, S. Turner. *Elliptic Curves for Security.* RFC 7748, 2016. [rfc-editor.org/rfc/rfc7748](https://www.rfc-editor.org/rfc/rfc7748). X25519.
3. Y. Nir, A. Langley. *ChaCha20 and Poly1305 for IETF Protocols.* RFC 8439, 2018 (obsoletes RFC 7539). [rfc-editor.org/rfc/rfc8439](https://www.rfc-editor.org/rfc/rfc8439).
4. H. Krawczyk, P. Eronen. *HMAC-based Extract-and-Expand Key Derivation Function (HKDF).* RFC 5869, 2010. [rfc-editor.org/rfc/rfc5869](https://www.rfc-editor.org/rfc/rfc5869).
5. C. Percival, S. Josefsson. *The scrypt Password-Based Key Derivation Function.* RFC 7914, 2016. [rfc-editor.org/rfc/rfc7914](https://www.rfc-editor.org/rfc/rfc7914). Private-key file KDF.
6. P. Wuille, G. Maxwell. *BIP 173: Base32 address format for native v0-16 witness outputs* (Bech32). [github.com/bitcoin/bips](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki). Public-key text encoding.
7. The age file format, [c2sp.org/age](https://c2sp.org/age): the text-header-plus-chunked-payload design that `pfsh` v1 follows loosely. (`pfsh` v1 is not age-compatible.)
8. M. Barbosa et al. *X-Wing: The Hybrid KEM You've Been Looking For.* IACR ePrint 2024/039, [eprint.iacr.org/2024/039](https://eprint.iacr.org/2024/039). The combiner this package does **not** yet use; see [SECURITY_NOTES.md](SECURITY_NOTES.md).
9. Test vectors: Project Wycheproof ML-KEM-768 files ([github.com/C2SP/wycheproof](https://github.com/C2SP/wycheproof)) and ACVP ML-KEM-768 key-generation and encapsulation/decapsulation files (NIST ACVP), both under `tests/kats/`.
10. liboqs, [github.com/open-quantum-safe/liboqs](https://github.com/open-quantum-safe/liboqs): the ML-KEM-768 implementation.

The URLs for items 2 to 4, 6 to 8 and 10 returned a response when fetched on 2026-10-25 (redirects for the RFC pages). The `pfsh` v1 format itself is specified only by this package's code.

## Method to code

| Element | Published method | Implementation |
|---|---|---|
| ML-KEM-768 keygen / encaps / decaps | FIPS 203 | `kem._mlkem_keypair`, `_mlkem_encaps`, `_mlkem_decaps` via liboqs `OQS_KEM_*` |
| X25519 | RFC 7748 | `kem.x25519_ecdh`, pyca `X25519PrivateKey.exchange`; low-order result raises `LowOrderX25519` |
| Hybrid combiner | Simple concatenation KDF (not X-Wing, not HPKE) | `kem._combine`: `HKDF-SHA256(ss_mlkem \|\| ss_x25519, salt="", info="pfsh-hybrid")` |
| Wrap key | HKDF (RFC 5869) | `header._derive_wrap_key`: `HKDF(K_hybrid, info="wrap")` |
| Wrapped file key | ChaCha20-Poly1305 (RFC 8439) | `header._encode_header`: 16-byte file key sealed under the wrap key with a fixed zero nonce (the wrap key is unique per stanza) |
| Header MAC | HMAC-SHA256 truncated to 16 bytes | `header._compute_mac`, key `HKDF(file_key, info="header")`; checked with `compare_digest` |
| Chunk keys | HKDF | `ae.derive_payload_key` / `chunker._derive_payload_key`: `HKDF(file_key, salt=chunk_nonce, info="payload")` |
| Chunk nonce | counter + final flag | `chunker._make_nonce`: 8-byte big-endian counter, 1-byte final flag, 3 zero bytes |
| Chunk size | fixed | 65,536 bytes (`CHUNK_SIZE`) |
| End marker | fixed | `"--- " + base64(16 zero bytes) + LF` |
| Downgrade policy | n/a (this package) | `encrypt._recover_file_key(require_pq=...)` raises `ClassicalOnlyRejected` |
| Private-key KDF | scrypt, RFC 7914 | `keys._derive_key_from_passphrase`, n=2^17, r=8, p=1 |
| Public-key encoding | Bech32 (BIP 173) | `keys.public_key_text` / `load_public_key` |

## Independent checks

- Wycheproof and ACVP ML-KEM-768 vectors are run against the liboqs binding (`tests/test_kat_wycheproof.py`, `tests/test_kat_acvp.py`).
- `tests/reference_oracle.py` is a separate, plain implementation of the file writer/reader; `tests/test_encrypt.py` checks that the chunk body from `encrypt` is bit-identical to the oracle's for the same file key, and that each reads the other's files.
- `tests/test_security_fixes.py` re-implements the private-key file layout (scrypt, AAD) independently of `keys.py` and decrypts a stored key with it.
