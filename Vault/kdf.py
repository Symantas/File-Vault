"""Key derivation functions.

A :class:`KeyDerivation` turns a human password plus a random salt into a fixed
length symmetric key. Keeping this behind an interface lets the cipher depend on
the *abstraction* (Dependency Inversion) so the algorithm can be swapped — for
example to Argon2 — without touching the encryption code.
"""

from abc import ABC, abstractmethod

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


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


class PBKDF2KeyDerivation(KeyDerivation):
    """PBKDF2-HMAC-SHA256 key derivation."""

    # OWASP-recommended minimum for PBKDF2-HMAC-SHA256 (2023).
    DEFAULT_ITERATIONS = 480_000

    def __init__(
        self,
        iterations: int = DEFAULT_ITERATIONS,
        key_size: int = 32,
        salt_size: int = 16,
    ) -> None:
        self._iterations = iterations
        self._key_size = key_size
        self._salt_size = salt_size

    @property
    def salt_size(self) -> int:
        return self._salt_size

    @property
    def key_size(self) -> int:
        return self._key_size

    def derive(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self._key_size,
            salt=salt,
            iterations=self._iterations,
        )
        return kdf.derive(password.encode("utf-8"))
