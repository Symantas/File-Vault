"""Password-based authenticated encryption.

An :class:`Encryptor` encrypts and decrypts byte strings using a password. The
default :class:`AesGcmEncryptor` composes a :class:`~Vault.kdf.KeyDerivation`
(injected dependency) with AES-256-GCM.

Blob layout::

    kdf_param_block | salt (kdf.salt_size) | nonce (12) | ciphertext (+ 16-byte tag)

The KDF parameter block makes the blob self-describing: decryption rebuilds the
exact KDF used at encryption time, so the default work factor can be raised
without breaking existing vaults. The parameter block and any caller-supplied
``associated_data`` (e.g. the container header) are authenticated as GCM AAD, so
neither can be tampered with or downgraded.

Each call uses a fresh random salt *and* nonce. A fresh salt means a fresh key
every time, so GCM's nonce-reuse pitfall cannot occur across calls.
"""

import os
from abc import ABC, abstractmethod

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import kdfparams
from .errors import ContainerError, DecryptionError
from .kdf import KeyDerivation, PBKDF2KeyDerivation

# Valid AES key lengths in bytes (128/192/256-bit).
_AES_KEY_SIZES = (16, 24, 32)


class Encryptor(ABC):
    """Encrypts and decrypts bytes with a password."""

    @abstractmethod
    def encrypt(self, data: bytes, password: str, associated_data: bytes = b"") -> bytes:
        """Return a self-contained encrypted blob for ``data``.

        ``associated_data`` is authenticated but not encrypted.
        """

    @abstractmethod
    def decrypt(self, blob: bytes, password: str, associated_data: bytes = b"") -> bytes:
        """Reverse :meth:`encrypt`.

        ``associated_data`` must match the value used at encryption time. Raises a
        :class:`~Vault.errors.VaultError` on failure — :class:`DecryptionError`
        for a wrong password or tampering, or :class:`~Vault.errors.ContainerError`
        for a malformed/unsupported parameter block.
        """


class AesGcmEncryptor(Encryptor):
    """AES-256-GCM encryption with a pluggable, self-describing KDF."""

    NONCE_SIZE = 12

    def __init__(self, kdf: KeyDerivation | None = None) -> None:
        self._kdf = kdf or PBKDF2KeyDerivation()

    def encrypt(self, data: bytes, password: str, associated_data: bytes = b"") -> bytes:
        param_block = kdfparams.serialize(self._kdf.params())
        salt = os.urandom(self._kdf.salt_size)
        nonce = os.urandom(self.NONCE_SIZE)
        key = self._kdf.derive(password, salt)
        ciphertext = AESGCM(key).encrypt(nonce, data, associated_data + param_block)
        return param_block + salt + nonce + ciphertext

    def decrypt(self, blob: bytes, password: str, associated_data: bytes = b"") -> bytes:
        # Rebuild the KDF from the stored parameters, not self._kdf, so a vault
        # always decrypts with the parameters it was created with.
        params, offset = kdfparams.deserialize(blob)
        if params.key_size not in _AES_KEY_SIZES:
            raise ContainerError("unsupported AES key size in vault")
        kdf = kdfparams.kdf_from_params(params)

        header_size = offset + kdf.salt_size + self.NONCE_SIZE
        if len(blob) < header_size:
            raise DecryptionError("blob is too short to be a valid payload")

        param_block = blob[:offset]
        salt = blob[offset : offset + kdf.salt_size]
        nonce = blob[offset + kdf.salt_size : header_size]
        ciphertext = blob[header_size:]

        key = kdf.derive(password, salt)
        try:
            return AESGCM(key).decrypt(nonce, ciphertext, associated_data + param_block)
        except InvalidTag as exc:
            raise DecryptionError(
                "decryption failed: wrong password or corrupted data"
            ) from exc
