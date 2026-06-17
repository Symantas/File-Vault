from Vault.kdf import (
    ALGO_PBKDF2_SHA256,
    ALGO_SCRYPT,
    PBKDF2KeyDerivation,
    ScryptKeyDerivation,
)


def test_pbkdf2_deterministic():
    kdf = PBKDF2KeyDerivation(iterations=1000)
    salt = b"0123456789abcdef"
    assert kdf.derive("pw", salt) == kdf.derive("pw", salt)


def test_pbkdf2_key_size():
    kdf = PBKDF2KeyDerivation(iterations=1000, key_size=32)
    assert len(kdf.derive("pw", b"x" * kdf.salt_size)) == 32
    assert kdf.key_size == 32
    assert kdf.salt_size == 16


def test_pbkdf2_salt_changes_key():
    kdf = PBKDF2KeyDerivation(iterations=1000)
    assert kdf.derive("pw", b"a" * 16) != kdf.derive("pw", b"b" * 16)


def test_pbkdf2_params():
    kdf = PBKDF2KeyDerivation(iterations=1000)
    p = kdf.params()
    assert p.algo_id == ALGO_PBKDF2_SHA256
    assert p.extra == {"iterations": 1000}
    assert (p.key_size, p.salt_size) == (32, 16)


def test_scrypt_deterministic():
    kdf = ScryptKeyDerivation(n=2**8, r=8, p=1)
    salt = b"0123456789abcdef"
    assert kdf.derive("pw", salt) == kdf.derive("pw", salt)


def test_scrypt_key_size_and_salt_sensitivity():
    kdf = ScryptKeyDerivation(n=2**8, r=8, p=1, key_size=32)
    assert len(kdf.derive("pw", b"x" * kdf.salt_size)) == 32
    assert kdf.derive("pw", b"a" * 16) != kdf.derive("pw", b"b" * 16)


def test_scrypt_params():
    kdf = ScryptKeyDerivation(n=2**8, r=8, p=1)
    p = kdf.params()
    assert p.algo_id == ALGO_SCRYPT
    assert p.extra == {"n": 2**8, "r": 8, "p": 1}
