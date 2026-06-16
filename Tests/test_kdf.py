from Vault.kdf import PBKDF2KeyDerivation


def test_deterministic():
    kdf = PBKDF2KeyDerivation(iterations=1000)
    salt = b"0123456789abcdef"
    assert kdf.derive("pw", salt) == kdf.derive("pw", salt)


def test_key_size():
    kdf = PBKDF2KeyDerivation(iterations=1000, key_size=32)
    assert len(kdf.derive("pw", b"x" * kdf.salt_size)) == 32
    assert kdf.key_size == 32
    assert kdf.salt_size == 16


def test_salt_changes_key():
    kdf = PBKDF2KeyDerivation(iterations=1000)
    assert kdf.derive("pw", b"a" * 16) != kdf.derive("pw", b"b" * 16)
