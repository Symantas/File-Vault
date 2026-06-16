"""Authenticated encryption primitives for File-Vault.

Data is encrypted with AES-256-GCM. The symmetric key is derived from a
user-supplied password using PBKDF2-HMAC-SHA256. Each encryption uses a fresh
random salt and nonce so the same password and plaintext never produce the same
ciphertext.

The on-the-wire layout produced by :func:`encrypt` is::

    salt (16 bytes) | nonce (12 bytes) | ciphertext (+ GCM tag)
"""

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# OWASP-recommended minimum for PBKDF2-HMAC-SHA256 (2023).
KDF_ITERATIONS = 480_000
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32  # AES-256


class DecryptionError(Exception):
    """Raised when a blob cannot be decrypted (wrong password or tampering)."""


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from ``password`` and ``salt`` via PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode())


def encrypt(data: bytes, password: str) -> bytes:
    """Encrypt ``data`` with ``password`` and return ``salt | nonce | ciphertext``."""
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return salt + nonce + ciphertext


def decrypt(blob: bytes, password: str) -> bytes:
    """Decrypt a blob produced by :func:`encrypt`.

    Raises:
        DecryptionError: if the password is wrong, the blob is truncated, or the
            data has been tampered with.
    """
    if len(blob) < SALT_SIZE + NONCE_SIZE:
        raise DecryptionError("blob is too short to be a valid vault payload")

    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = blob[SALT_SIZE + NONCE_SIZE:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise DecryptionError(
            "decryption failed: wrong password or corrupted data"
        ) from exc
