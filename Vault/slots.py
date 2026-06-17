"""Key slots: independent wrappings of a vault's Data Encryption Key (DEK).

The payload is encrypted once under a random per-vault DEK. Each key slot stores
that DEK encrypted under a different key-encryption key (KEK), so a vault can be
unlocked by any of several secrets (passwords now; X25519 recipients in a later
phase). Adding or removing a slot only rewraps the 48-byte DEK — the bulk payload
is never re-encrypted.

A slot's wrap AAD is ``container_header || slot_type`` so a slot is bound to the
format version and cannot be reinterpreted as a different slot type.
"""

import os
from abc import ABC, abstractmethod

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import kdfparams
from .errors import ContainerError
from .kdf import KeyDerivation

DEK_SIZE = 32  # AES-256 data key
WRAP_NONCE_SIZE = 12

SLOT_PASSWORD = 1
SLOT_X25519 = 2

_SLOT_NAMES = {SLOT_PASSWORD: "password", SLOT_X25519: "x25519"}


def slot_name(slot_type: int) -> str:
    """Human-readable slot-type name (for ``info``, no unlocking needed)."""
    try:
        return _SLOT_NAMES[slot_type]
    except KeyError:
        raise ContainerError(f"unsupported key-slot type: {slot_type}")


class KeySlot(ABC):
    """Builds a slot body that wraps the DEK for one secret."""

    slot_type: int

    @abstractmethod
    def wrap(self, dek: bytes, slot_aad: bytes) -> bytes:
        """Return the slot's body bytes (type/length framing is added elsewhere)."""


class PasswordSlot(KeySlot):
    """Wraps the DEK with a KEK derived from a password.

    Body layout: ``kdf_param_block | salt | wrap_nonce(12) | wrapped_dek(+tag)``.
    """

    slot_type = SLOT_PASSWORD

    def __init__(self, kdf: KeyDerivation, password: str) -> None:
        self._kdf = kdf
        self._password = password

    def wrap(self, dek: bytes, slot_aad: bytes) -> bytes:
        salt = os.urandom(self._kdf.salt_size)
        nonce = os.urandom(WRAP_NONCE_SIZE)
        kek = self._kdf.derive(self._password, salt)
        wrapped = AESGCM(kek).encrypt(nonce, dek, slot_aad)
        return kdfparams.serialize(self._kdf.params()) + salt + nonce + wrapped

    @staticmethod
    def unlock(body: bytes, password: str, slot_aad: bytes) -> bytes | None:
        """Recover the DEK from a password slot, or ``None`` on a wrong password.

        Raises :class:`ContainerError` only for a malformed body.
        """
        params, offset = kdfparams.deserialize(body)
        kdf = kdfparams.kdf_from_params(params)
        need = offset + kdf.salt_size + WRAP_NONCE_SIZE
        if len(body) < need:
            raise ContainerError("password slot body is truncated")
        salt = body[offset : offset + kdf.salt_size]
        nonce = body[offset + kdf.salt_size : need]
        wrapped = body[need:]
        kek = kdf.derive(password, salt)
        try:
            return AESGCM(kek).decrypt(nonce, wrapped, slot_aad)
        except InvalidTag:
            return None


def unlock_slot(
    slot_type: int,
    body: bytes,
    slot_aad: bytes,
    *,
    password: str | None = None,
    identity: object | None = None,
) -> bytes | None:
    """Try to recover the DEK from one slot using whatever secret is available.

    Returns the DEK on success, or ``None`` if the supplied secret doesn't fit
    this slot (wrong password, or no matching secret kind provided).
    """
    if slot_type == SLOT_PASSWORD:
        if password is None:
            return None
        return PasswordSlot.unlock(body, password, slot_aad)
    if slot_type == SLOT_X25519:
        if identity is None:
            return None
        return RecipientSlot.unlock(body, identity, slot_aad)
    raise ContainerError(f"unsupported key-slot type: {slot_type}")
