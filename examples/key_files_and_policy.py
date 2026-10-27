"""Store keys on disk under a passphrase, then show the classical-only downgrade policy."""
import os
import tempfile

from pqblocks_files.encrypt import decrypt, encrypt
from pqblocks_files.keys import keygen, load_private_key, load_public_key, save_private_key, save_public_key
from pqblocks_files.pqtypes import ClassicalOnlyRejected, KeyPair

passphrase = os.urandom(12).hex().encode()           # demo only: use a prompt or a secret store
kp = keygen()
with tempfile.TemporaryDirectory() as d:
    pub, priv = os.path.join(d, "pub.sec"), os.path.join(d, "priv.sec")
    save_public_key(kp, pub)
    save_private_key(kp, priv, passphrase)           # scrypt + random salt, mode 0600
    recipient = load_public_key(pub)
    loaded = KeyPair(public=recipient, private=load_private_key(priv, passphrase))

    blob = encrypt(b"stored-key round trip", [recipient])
    assert decrypt(blob, loaded) == b"stored-key round trip"

    classical = encrypt(b"x25519 only", [recipient], classical_only=True)   # explicit opt-in to write
    try:
        decrypt(classical, loaded)                   # default policy refuses a classical-only file
        raise SystemExit("downgrade was not rejected")
    except ClassicalOnlyRejected:
        print("classical-only file rejected by default")
    assert decrypt(classical, loaded, require_pq=False) == b"x25519 only"
    print("key files and downgrade policy ok")
