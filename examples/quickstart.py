"""Encrypt a message to a hybrid public key and decrypt it again (round-trip check)."""
from pqblocks_files.encrypt import decrypt_with_mode, encrypt, MODE_HYBRID
from pqblocks_files.keys import keygen

keypair = keygen()                                   # ML-KEM-768 + X25519
message = b"hello, post-quantum world" * 1000
blob = encrypt(message, [keypair.public])            # fresh random file key every call
result = decrypt_with_mode(blob, keypair)            # require_pq=True by default
assert result.plaintext == message
assert result.mode == MODE_HYBRID
print("round-trip ok:", len(message), "->", len(blob), "bytes, mode =", result.mode)
