"""Shared passphrase plumbing for the CLI tests: the CLI has no default passphrase, so every
keygen/decrypt call in the suites passes --passphrase-file pointing at this fixed test file."""

import atexit
import os
import shutil
import tempfile

TEST_PASSPHRASE = b"test-suite passphrase (not a secret)"
_DIR = tempfile.mkdtemp(prefix="pqblocks-test-pass-")
atexit.register(shutil.rmtree, _DIR, ignore_errors=True)
PASSFILE = os.path.join(_DIR, "passphrase.txt")
with open(PASSFILE, "wb") as _fh:
    _fh.write(TEST_PASSPHRASE + b"\n")


def with_passphrase(argv):
    """Append --passphrase-file for keygen/decrypt unless the call already has one or asks for help."""
    argv = list(argv)
    if argv and argv[0] in ("keygen", "decrypt") and "--passphrase-file" not in argv \
            and "--help" not in argv and "-h" not in argv:
        argv += ["--passphrase-file", PASSFILE]
    return argv
