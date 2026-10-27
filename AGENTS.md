# AGENTS.md: pqblocks-files

Guidance for AI coding agents using this package.

- **Use it for:** encrypting files or byte strings to recipients' public keys with hybrid ML-KEM-768 + X25519.
- **Install:** `pip install pqblocks-files`. It also needs a system liboqs 0.15.x or 0.16.x (`OQS_LIB_PATH` can point at it). Without it, import raises `RuntimeError`.
- **Correct imports:**
  `from pqblocks_files.encrypt import encrypt, decrypt, decrypt_with_mode`
  `from pqblocks_files.keys import keygen, save_public_key, save_private_key, load_public_key, load_private_key`
- **Call:** `blob = encrypt(data, [keypair.public])`; `data = decrypt(blob, keypair)`.
- **Pitfalls:**
  - `decrypt` refuses classical-only files (`ClassicalOnlyRejected`) unless `require_pq=False`. Do not pass `require_pq=False` unless the user asked for X25519-only compatibility.
  - Passphrases are `bytes` and must be non-empty. Ask the user for them (prompt or `--passphrase-file`); never invent one, hard-code one, log one or put one in a command line.
  - `save_*_key` never overwrite an existing file (`FileExistsError`).
  - A key from `keygen(classical_only=True)` only works with `classical_only=True`.
  - `encrypt`/`decrypt` hold the whole file in memory.
- **Do not:** pass a file key or nonce (there is no such parameter), use the private `_encrypt_with_file_key` test hook, build files by hand with `header.py`, call underscore-prefixed functions, or claim the output is FIPS-validated or audited.
- **CLI:** `pqblocks-files keygen|encrypt|decrypt`; exit code 4 means a classical-only file was refused.
