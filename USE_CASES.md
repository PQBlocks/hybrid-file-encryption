# Use cases

All snippets assume `from pqblocks_files.keys import keygen` and a liboqs installation (see README).

## 1. Protect an archive against "harvest now, decrypt later"

Back up sensitive files today to a key that quantum computers are expected to threaten later.

```python
from pqblocks_files.encrypt import encrypt, decrypt
from pqblocks_files.keys import keygen

backup_key = keygen()
archive = b"customer records ..." * 10_000
blob = encrypt(archive, [backup_key.public])
assert decrypt(blob, backup_key) == archive
```

## 2. Share a file with a team: several recipients

Any one of the private keys opens the file; every recipient has their own stanza.

```python
alice, bob = keygen(), keygen()
blob = encrypt(b"design doc", [alice.public, bob.public])
assert decrypt(blob, alice) == decrypt(blob, bob) == b"design doc"
```

## 3. Keys on disk, passphrase-protected

```python
import os, tempfile
from pqblocks_files.keys import save_private_key, load_private_key

kp = keygen()
with tempfile.TemporaryDirectory() as d:
    path = os.path.join(d, "me.key")
    save_private_key(kp, path, b"a long passphrase")       # random salt, scrypt, mode 0600
    assert load_private_key(path, b"a long passphrase") == kp.private
```

## 4. Refuse a downgraded file

An attacker (or an old tool) hands you a file whose only stanza for you is X25519-only. The default policy refuses it.

```python
from pqblocks_files.pqtypes import ClassicalOnlyRejected

kp = keygen()
weak = encrypt(b"data", [kp.public], classical_only=True)
try:
    decrypt(weak, kp)
except ClassicalOnlyRejected:
    print("refused: not post-quantum protected")
```

## 5. Command-line encryption in a script

```bash
echo 'correct horse battery staple' > pass.txt && chmod 600 pass.txt
pqblocks-files keygen --output me.pub --output-sec me.key --passphrase-file pass.txt
pqblocks-files encrypt --recipient me.pub --output notes.pfsh notes.txt
pqblocks-files decrypt --key me.key --passphrase-file pass.txt --output notes.out notes.pfsh
```
