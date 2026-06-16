"""Password-based authenticated encryption.

An :class:`Encryptor` encrypts and decrypts byte strings using a password. The
default :class:`AesGcmEncryptor` composes a :class:`~Vault.kdf.KeyDerivation`
(injected dependency) with AES-256-GCM.

Blob layout::

    salt (kdf.salt_size) | nonce (12) | ciphertext (+ 16-byte GCM tag)

Each call uses a fresh random salt *and* nonce. A fresh salt means a fresh key
every time, so GCM's nonce-reuse pitfall cannot occur across calls.
"""

import os
from abc import ABC, abstractmethod

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import DecryptionError
from .kdf import KeyDerivation, PBKDF2KeyDerivation


class Encryptor(ABC):
    """Encrypts and decrypts bytes with a password."""

    @abstractmethod
    def encrypt(self, data: bytes, password: str) -> bytes:
        """Return a self-contained encrypted blob for ``data``."""

    @abstractmethod
    def decrypt(self, blob: bytes, password: str) -> bytes:
        """Reverse :meth:`encrypt`, raising :class:`DecryptionError` on failure."""


class AesGcmEncryptor(Encryptor):
    """AES-256-GCM encryption with a pluggable key-derivation function."""

    NONCE_SIZE = 12

    def __init__(self, kdf: KeyDerivation | None = None) -> None:
        self._kdf = kdf or PBKDF2KeyDerivation()

    def encrypt(self, data: bytes, password: str) -> bytes:
        salt = os.urandom(self._kdf.salt_size)
        nonce = os.urandom(self.NONCE_SIZE)
        key = self._kdf.derive(password, salt)
        ciphertext = AESGCM(key).encrypt(nonce, data, None)
        return salt + nonce + ciphertext

    def decrypt(self, blob: bytes, password: str) -> bytes:
        header_size = self._kdf.salt_size + self.NONCE_SIZE
        if len(blob) < header_size:
            raise DecryptionError("blob is too short to be a valid payload")

        salt = blob[: self._kdf.salt_size]
        nonce = blob[self._kdf.salt_size : header_size]
        ciphertext = blob[header_size:]

        key = self._kdf.derive(password, salt)
        try:
            return AESGCM(key).decrypt(nonce, ciphertext, None)
        except InvalidTag as exc:
            raise DecryptionError(
                "decryption failed: wrong password or corrupted data"
            ) from exc
