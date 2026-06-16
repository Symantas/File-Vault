import pytest

from Vault.cipher import AesGcmEncryptor
from Vault.errors import DecryptionError
from Vault.kdf import PBKDF2KeyDerivation


@pytest.fixture
def encryptor():
    # Low iteration count keeps the test suite fast.
    return AesGcmEncryptor(PBKDF2KeyDerivation(iterations=1000))


def test_round_trip(encryptor):
    blob = encryptor.encrypt(b"the quick brown fox", "pw")
    assert encryptor.decrypt(blob, "pw") == b"the quick brown fox"


def test_round_trip_empty(encryptor):
    assert encryptor.decrypt(encryptor.encrypt(b"", "pw"), "pw") == b""


def test_ciphertext_is_randomized(encryptor):
    assert encryptor.encrypt(b"data", "pw") != encryptor.encrypt(b"data", "pw")


def test_wrong_password_raises(encryptor):
    blob = encryptor.encrypt(b"secret", "right")
    with pytest.raises(DecryptionError):
        encryptor.decrypt(blob, "wrong")


def test_tampered_blob_raises(encryptor):
    blob = bytearray(encryptor.encrypt(b"secret", "pw"))
    blob[-1] ^= 0xFF
    with pytest.raises(DecryptionError):
        encryptor.decrypt(bytes(blob), "pw")


def test_truncated_blob_raises(encryptor):
    with pytest.raises(DecryptionError):
        encryptor.decrypt(b"short", "pw")
