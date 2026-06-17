"""Key derivation functions.

A :class:`KeyDerivation` turns a human password plus a random salt into a fixed
length symmetric key. Keeping this behind an interface lets the cipher depend on
the *abstraction* (Dependency Inversion) so the algorithm can be swapped without
touching the encryption code.

Each KDF can also report its algorithm id and parameters via :meth:`params`, so
they can be stored alongside the ciphertext. That lets a vault be decrypted with
the exact parameters it was created with — and lets the default work factor be
raised over time without making existing vaults undecryptable.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Algorithm identifiers persisted in the KDF parameter block. Kept here (with the
# KDF classes) so kdfparams.py can import them without a circular dependency.
ALGO_PBKDF2_SHA256 = 1
ALGO_SCRYPT = 2


@dataclass(frozen=True)
class KdfParams:
    """Self-describing parameters needed to reconstruct a :class:`KeyDerivation`."""

    algo_id: int
    key_size: int
    salt_size: int
    extra: dict[str, int]  # PBKDF2: {"iterations"}; scrypt: {"n", "r", "p"}


class KeyDerivation(ABC):
    """Derives a symmetric key from a password and salt."""

    @property
    @abstractmethod
    def salt_size(self) -> int:
        """Number of random salt bytes this KDF expects."""

    @property
    @abstractmethod
    def key_size(self) -> int:
        """Length in bytes of the derived key."""

    @abstractmethod
    def derive(self, password: str, salt: bytes) -> bytes:
        """Derive a key of ``key_size`` bytes."""

    @abstractmethod
    def params(self) -> KdfParams:
        """Report this KDF's algorithm id and parameters for serialization."""


class _SizedKeyDerivation(KeyDerivation):
    """Base for KDFs that carry a key size and salt size, providing both."""

    def __init__(self, key_size: int, salt_size: int) -> None:
        self._key_size = key_size
        self._salt_size = salt_size

    @property
    def salt_size(self) -> int:
        return self._salt_size

    @property
    def key_size(self) -> int:
        return self._key_size


class PBKDF2KeyDerivation(_SizedKeyDerivation):
    """PBKDF2-HMAC-SHA256 key derivation."""

    # OWASP-recommended minimum for PBKDF2-HMAC-SHA256 (2023).
    DEFAULT_ITERATIONS = 480_000

    def __init__(
        self,
        iterations: int = DEFAULT_ITERATIONS,
        key_size: int = 32,
        salt_size: int = 16,
    ) -> None:
        super().__init__(key_size, salt_size)
        self._iterations = iterations

    def derive(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self._key_size,
            salt=salt,
            iterations=self._iterations,
        )
        return kdf.derive(password.encode("utf-8"))

    def params(self) -> KdfParams:
        return KdfParams(
            ALGO_PBKDF2_SHA256,
            self._key_size,
            self._salt_size,
            {"iterations": self._iterations},
        )


class ScryptKeyDerivation(_SizedKeyDerivation):
    """scrypt key derivation — memory-hard, resists GPU/ASIC brute forcing.

    Available without any extra dependency (it ships with ``cryptography``).
    """

    # ~128 MiB (128 * n * r bytes) at the defaults — a strong interactive cost.
    DEFAULT_N = 2**17
    DEFAULT_R = 8
    DEFAULT_P = 1

    def __init__(
        self,
        n: int = DEFAULT_N,
        r: int = DEFAULT_R,
        p: int = DEFAULT_P,
        key_size: int = 32,
        salt_size: int = 16,
    ) -> None:
        super().__init__(key_size, salt_size)
        self._n = n
        self._r = r
        self._p = p

    def derive(self, password: str, salt: bytes) -> bytes:
        kdf = Scrypt(
            salt=salt,
            length=self._key_size,
            n=self._n,
            r=self._r,
            p=self._p,
        )
        return kdf.derive(password.encode("utf-8"))

    def params(self) -> KdfParams:
        return KdfParams(
            ALGO_SCRYPT,
            self._key_size,
            self._salt_size,
            {"n": self._n, "r": self._r, "p": self._p},
        )
