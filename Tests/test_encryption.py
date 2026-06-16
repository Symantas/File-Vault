import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Vault import encryption  # noqa: E402
from Vault.encryption import DecryptionError  # noqa: E402


def test_round_trip():
    data = b"the quick brown fox"
    blob = encryption.encrypt(data, "correct horse battery staple")
    assert encryption.decrypt(blob, "correct horse battery staple") == data


def test_round_trip_empty_data():
    blob = encryption.encrypt(b"", "pw")
    assert encryption.decrypt(blob, "pw") == b""


def test_ciphertext_is_randomized():
    # Same input twice should yield different blobs (fresh salt + nonce).
    a = encryption.encrypt(b"data", "pw")
    b = encryption.encrypt(b"data", "pw")
    assert a != b


def test_wrong_password_raises():
    blob = encryption.encrypt(b"secret", "right")
    with pytest.raises(DecryptionError):
        encryption.decrypt(blob, "wrong")


def test_tampered_ciphertext_raises():
    blob = bytearray(encryption.encrypt(b"secret", "pw"))
    blob[-1] ^= 0xFF  # flip a bit in the GCM tag
    with pytest.raises(DecryptionError):
        encryption.decrypt(bytes(blob), "pw")


def test_truncated_blob_raises():
    with pytest.raises(DecryptionError):
        encryption.decrypt(b"too short", "pw")


def test_derive_key_is_deterministic():
    salt = b"0123456789abcdef"
    assert encryption.derive_key("pw", salt) == encryption.derive_key("pw", salt)
    assert len(encryption.derive_key("pw", salt)) == encryption.KEY_SIZE
