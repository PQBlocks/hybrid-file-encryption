"""Shared types and exceptions for pqblocks-files."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Recipient:
    hybrid_pk: bytes  # 1216B: mlkem_pk(1184) || x25519_pk(32)
    label: str = ""


@dataclass(frozen=True)
class KeyPair:
    public: Recipient
    private: bytes = field(repr=False)  # 2432B: mlkem_sk(2400) || x25519_sk(32); never shown in repr


class HeaderMACMismatch(Exception):
    pass


class TruncatedFile(Exception):
    pass


class TagVerificationFailed(Exception):
    pass


class MLKEMKeyCheckFailed(Exception):
    pass


class LowOrderX25519(ValueError):
    """X25519 exchange with a low-order point (all-zero shared secret)."""


class ClassicalOnlyRejected(Exception):
    """The file is readable by this key only through an X25519-only (not post-quantum) stanza,
    and the caller did not opt in with require_pq=False."""


class NonMonotonicCounter(Exception):
    pass


class SeekNotPermitted(Exception):
    pass
