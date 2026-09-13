"""X25519 identities and recipients for public-key vaults.

A :class:`Recipient` is a public key you can encrypt *to*; an :class:`Identity`
is the matching private key that can unlock such a vault. This lets someone share
an encrypted vault with you without ever sharing a password.

Keys are encoded as a short ASCII prefix plus unpadded base64url — simple,
dependency-free, and copy-paste safe. Integrity is provided cryptographically
(the recipient public key is bound into each slot via the HKDF salt and GCM AAD),
so the encoding itself needs no checksum.
"""

import base64

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .errors import VaultError

PUBLIC_PREFIX = "agevault-pub-"
SECRET_PREFIX = "AGEVAULT-SECRET-KEY-"
_KEY_LEN = 32


class IdentityError(VaultError):
    """Raised when a key string or key file is malformed."""


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + pad)
    except (ValueError, base64.binascii.Error) as exc:
        raise IdentityError("malformed key encoding") from exc


class Recipient:
    """An X25519 public key that a vault can be encrypted to."""

    def __init__(self, public_bytes: bytes) -> None:
        if len(public_bytes) != _KEY_LEN:
            raise IdentityError("invalid X25519 public key length")
        self.public_bytes = public_bytes

    @classmethod
    def parse(cls, encoded: str) -> "Recipient":
        encoded = encoded.strip()
        if not encoded.startswith(PUBLIC_PREFIX):
            raise IdentityError("not a recipient public key (bad prefix)")
        return cls(_b64decode(encoded[len(PUBLIC_PREFIX):]))

    def encode(self) -> str:
        return PUBLIC_PREFIX + _b64encode(self.public_bytes)

    def public_key(self) -> X25519PublicKey:
        return X25519PublicKey.from_public_bytes(self.public_bytes)


class Identity:
    """An X25519 private key that can unlock vaults encrypted to its recipient."""

    def __init__(self, private_key: X25519PrivateKey) -> None:
        self._private_key = private_key

    @classmethod
    def generate(cls) -> "Identity":
        return cls(X25519PrivateKey.generate())

    @classmethod
    def parse(cls, encoded: str) -> "Identity":
        encoded = encoded.strip()
        if not encoded.startswith(SECRET_PREFIX):
            raise IdentityError("not a secret key (bad prefix)")
        raw = _b64decode(encoded[len(SECRET_PREFIX):])
        if len(raw) != _KEY_LEN:
            raise IdentityError("invalid X25519 private key length")
        return cls(X25519PrivateKey.from_private_bytes(raw))

    @classmethod
    def load(cls, path: str) -> "Identity":
        with open(path, "r", encoding="ascii") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    return cls.parse(line)
        raise IdentityError(f"no key found in {path}")

    def encode(self) -> str:
        raw = self._private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )
        return SECRET_PREFIX + _b64encode(raw)

    def recipient(self) -> Recipient:
        raw = self._private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return Recipient(raw)

    def exchange(self, peer_public_bytes: bytes) -> bytes:
        return self._private_key.exchange(
            X25519PublicKey.from_public_bytes(peer_public_bytes)
        )
