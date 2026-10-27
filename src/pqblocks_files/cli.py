"""Command-line interface.

  pqblocks-files keygen [--output pub.sec] [--output-sec priv.sec] [--passphrase-file FILE] [--classical]
  pqblocks-files encrypt --recipient pub.sec [--recipient pub2.sec] [--output out.pfsh] [--classical] [-]
  pqblocks-files decrypt --key priv.sec [--passphrase-file FILE] [--allow-classical] [--output out.bin] in.pfsh

The private-key passphrase is read from a terminal prompt (getpass) or from --passphrase-file.
It is never taken from an argument, never has a default, and is never printed.

Exit codes:
  0 = Success
  1 = Bad input / malformed file / MAC failure / unusable passphrase
  2 = Key not found in header / private key could not be unlocked
  3 = ML-KEM key-check abort
  4 = File is classical-only (not post-quantum) and --allow-classical was not given
"""

from __future__ import annotations

import getpass
import sys
from argparse import ArgumentParser, Namespace
from typing import List, Optional

from pqblocks_files.encrypt import MODE_CLASSICAL, decrypt_with_mode, encrypt
from pqblocks_files.keys import (
    keygen,
    load_private_key,
    load_public_key,
    public_key_text,
    save_private_key,
    save_public_key,
)
from pqblocks_files.pqtypes import (
    ClassicalOnlyRejected,
    HeaderMACMismatch,
    KeyPair,
    MLKEMKeyCheckFailed,
    Recipient,
    TagVerificationFailed,
    TruncatedFile,
)

_MAX_PASSPHRASE_FILE = 4096


def _read_passphrase_file(path: str) -> bytes:
    """Contents of the file minus one trailing newline. Refuses an empty passphrase."""
    with open(path, "rb") as fh:
        data = fh.read(_MAX_PASSPHRASE_FILE + 1)
    if len(data) > _MAX_PASSPHRASE_FILE:
        raise ValueError(f"passphrase file is larger than {_MAX_PASSPHRASE_FILE} bytes")
    if data.endswith(b"\r\n"):
        data = data[:-2]
    elif data.endswith(b"\n"):
        data = data[:-1]
    if not data:
        raise ValueError("passphrase file is empty")
    return data


def _get_passphrase(args: Namespace, confirm: bool) -> bytes:
    """Passphrase from --passphrase-file, else an interactive prompt. Never empty."""
    if args.passphrase_file:
        return _read_passphrase_file(args.passphrase_file)
    first = getpass.getpass("Passphrase: ")
    if confirm and getpass.getpass("Repeat passphrase: ") != first:
        raise ValueError("passphrases do not match")
    if not first:
        raise ValueError("passphrase must not be empty")
    return first.encode("utf-8")


def _cmd_keygen(args: Namespace) -> int:
    """Generate a keypair."""
    passphrase: Optional[bytes] = None
    if args.output_sec:
        try:
            passphrase = _get_passphrase(args, confirm=True)
        except (OSError, ValueError) as exc:
            print(f"Passphrase error: {exc}", file=sys.stderr)
            return 1
    kp = keygen(classical_only=args.classical)

    try:
        if args.output_sec:
            save_private_key(kp, args.output_sec, passphrase)
            print(f"Private key written to {args.output_sec}", file=sys.stderr)
        else:
            print("Warning: no --output-sec given, the private key is discarded", file=sys.stderr)
        if args.output:
            save_public_key(kp, args.output)
            print(f"Public key written to {args.output}", file=sys.stderr)
        else:
            print(public_key_text(kp))
    except OSError as exc:
        print(f"Failed to write key file: {exc}", file=sys.stderr)
        return 1
    return 0


def _cmd_encrypt(args: Namespace) -> int:
    """Encrypt a file."""
    recipients: List[Recipient] = []
    for rec_path in args.recipient:
        try:
            recipients.append(load_public_key(rec_path))
        except (OSError, ValueError) as exc:
            print(f"Failed to load recipient {rec_path}: {exc}", file=sys.stderr)
            return 1

    if args.input == "-":
        plaintext = sys.stdin.buffer.read()
    else:
        try:
            with open(args.input, "rb") as f:
                plaintext = f.read()
        except FileNotFoundError as exc:
            print(f"Input file not found: {exc}", file=sys.stderr)
            return 1

    try:
        encrypted = encrypt(plaintext, recipients, classical_only=args.classical)
    except Exception as exc:
        print(f"Encryption failed: {exc}", file=sys.stderr)
        return 1

    return _write_output(args.output, encrypted, "Encrypted file")


def _write_output(output_path: Optional[str], data: bytes, label: str) -> int:
    if output_path and output_path != "-":
        try:
            with open(output_path, "wb") as f:
                f.write(data)
            print(f"{label} written to {output_path}", file=sys.stderr)
        except IOError as exc:
            print(f"Failed to write output: {exc}", file=sys.stderr)
            return 1
    else:
        sys.stdout.buffer.write(data)
    return 0


def _cmd_decrypt(args: Namespace) -> int:
    """Decrypt a file."""
    from pqblocks_files.kem import HYBRID_PK_LEN

    try:
        passphrase = _get_passphrase(args, confirm=False)
    except (OSError, ValueError) as exc:
        print(f"Passphrase error: {exc}", file=sys.stderr)
        return 1
    try:
        private = load_private_key(args.key, passphrase)
    except FileNotFoundError:
        print(f"Private key file not found: {args.key}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Failed to load key: {exc}", file=sys.stderr)
        return 2
    # decrypt() matches stanzas with the private key only; the public half is a placeholder.
    keypair = KeyPair(public=Recipient(hybrid_pk=b"\x00" * HYBRID_PK_LEN), private=private)

    try:
        with open(args.input, "rb") as f:
            pfsh_bytes = f.read()
    except FileNotFoundError as exc:
        print(f"Input file not found: {exc}", file=sys.stderr)
        return 1

    try:
        result = decrypt_with_mode(pfsh_bytes, keypair, require_pq=not args.allow_classical)
    except ClassicalOnlyRejected:
        print(
            "File is classical-only (X25519, not post-quantum). "
            "Re-run with --allow-classical to accept it.",
            file=sys.stderr,
        )
        return 4
    except HeaderMACMismatch:
        print("Key not found in header", file=sys.stderr)
        return 2
    except TagVerificationFailed as exc:
        print(f"Tag verification failed: {exc}", file=sys.stderr)
        return 1
    except MLKEMKeyCheckFailed as exc:
        print(f"ML-KEM key-check failed: {exc}", file=sys.stderr)
        return 3
    except TruncatedFile as exc:
        print(f"Truncated file: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Decryption failed: {exc}", file=sys.stderr)
        return 1

    if result.mode == MODE_CLASSICAL:
        print("Note: opened through a classical-only (X25519) stanza; not post-quantum protected.",
              file=sys.stderr)
    return _write_output(args.output, result.plaintext, "Decrypted file")


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point. Returns exit code per contract."""
    parser = ArgumentParser(prog="pqblocks-files")
    subparsers = parser.add_subparsers(dest="command")

    keygen_parser = subparsers.add_parser("keygen", help="Generate a keypair")
    keygen_parser.add_argument("--output", "-o", help="Public key output path (default: print to stdout)")
    keygen_parser.add_argument("--output-sec", help="Private key output path (encrypted under a passphrase)")
    keygen_parser.add_argument("--passphrase-file", help="Read the private-key passphrase from this file instead of prompting")
    keygen_parser.add_argument("--classical", action="store_true", help="X25519-only key (no post-quantum protection)")

    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    encrypt_parser.add_argument("--recipient", "-r", required=True, action="append", help="Public key file(s)")
    encrypt_parser.add_argument("--output", "-o", help="Output file path")
    encrypt_parser.add_argument("--classical", action="store_true", help="X25519-only stanzas (no post-quantum protection)")
    encrypt_parser.add_argument("input", help="Input file or '-' for stdin")

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    decrypt_parser.add_argument("--key", "-k", required=True, help="Private key file")
    decrypt_parser.add_argument("--passphrase-file", help="Read the private-key passphrase from this file instead of prompting")
    decrypt_parser.add_argument("--allow-classical", action="store_true", help="Accept files that are only readable through a classical-only (X25519) stanza")
    decrypt_parser.add_argument("--output", "-o", help="Output file path")
    decrypt_parser.add_argument("input", help="Input file")

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help(sys.stderr)
        return 1
    if args.command == "keygen":
        return _cmd_keygen(args)
    if args.command == "encrypt":
        return _cmd_encrypt(args)
    return _cmd_decrypt(args)


if __name__ == "__main__":
    sys.exit(main())
