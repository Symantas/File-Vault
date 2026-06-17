import os

import pytest

from Vault.errors import ContainerError
from Vault.kdf import PBKDF2KeyDerivation
from Vault.slots import (
    DEK_SIZE,
    SLOT_PASSWORD,
    PasswordSlot,
    slot_name,
    unlock_slot,
)

AAD = b"FVLT\x04\x01"


@pytest.fixture
def kdf():
    return PBKDF2KeyDerivation(iterations=1000)


def test_password_slot_wrap_unlock_round_trip(kdf):
    dek = os.urandom(DEK_SIZE)
    body = PasswordSlot(kdf, "correct password").wrap(dek, AAD)
    assert PasswordSlot.unlock(body, "correct password", AAD) == dek


def test_wrong_password_returns_none(kdf):
    dek = os.urandom(DEK_SIZE)
    body = PasswordSlot(kdf, "right").wrap(dek, AAD)
    assert PasswordSlot.unlock(body, "wrong", AAD) is None


def test_wrong_aad_returns_none(kdf):
    dek = os.urandom(DEK_SIZE)
    body = PasswordSlot(kdf, "pw").wrap(dek, AAD)
    assert PasswordSlot.unlock(body, "pw", b"FVLT\x04\x02") is None


def test_tampered_body_returns_none(kdf):
    dek = os.urandom(DEK_SIZE)
    body = bytearray(PasswordSlot(kdf, "pw").wrap(dek, AAD))
    body[-1] ^= 0xFF
    assert PasswordSlot.unlock(bytes(body), "pw", AAD) is None


def test_malformed_body_raises(kdf):
    with pytest.raises(ContainerError):
        PasswordSlot.unlock(b"too short", "pw", AAD)


def test_unlock_slot_dispatch(kdf):
    dek = os.urandom(DEK_SIZE)
    body = PasswordSlot(kdf, "pw").wrap(dek, AAD)
    assert unlock_slot(SLOT_PASSWORD, body, AAD, password="pw") == dek
    assert unlock_slot(SLOT_PASSWORD, body, AAD, password="bad") is None
    # No password supplied -> can't unlock a password slot.
    assert unlock_slot(SLOT_PASSWORD, body, AAD, identity=object()) is None


def test_slot_name():
    assert slot_name(SLOT_PASSWORD) == "password"
    with pytest.raises(ContainerError):
        slot_name(0x99)
