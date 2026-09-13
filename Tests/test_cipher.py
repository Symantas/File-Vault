import pytest

from Vault import kdfparams
from Vault.cipher import AesGcmEncryptor
from Vault.errors import ContainerError, DecryptionError, VaultError
from Vault.kdf import PBKDF2KeyDerivation, ScryptKeyDerivation


@pytest.fixture
def encryptor():
    # Low work factor keeps the test suite fast.
    return AesGcmEncryptor(PBKDF2KeyDerivation(iterations=1000))


@pytest.fixture
def scrypt_encryptor():
    return AesGcmEncryptor(ScryptKeyDerivation(n=2**8, r=8, p=1))


def test_round_trip(encryptor):
    blob = encryptor.encrypt(b"the quick brown fox", "pw")
    assert encryptor.decrypt(blob, "pw") == b"the quick brown fox"


def test_round_trip_empty(encryptor):
    assert encryptor.decrypt(encryptor.encrypt(b"", "pw"), "pw") == b""


def test_scrypt_round_trip(scrypt_encryptor):
    blob = scrypt_encryptor.encrypt(b"secret", "pw")
    assert scrypt_encryptor.decrypt(blob, "pw") == b"secret"


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
    # Garbage shorter than a parameter block -> ContainerError (a VaultError).
    with pytest.raises(VaultError):
        encryptor.decrypt(b"short", "pw")


def test_aad_mismatch_raises(encryptor):
    blob = encryptor.encrypt(b"secret", "pw", associated_data=b"FVLT\x03")
    with pytest.raises(DecryptionError):
        encryptor.decrypt(blob, "pw", associated_data=b"FVLT\x02")


def test_param_block_tamper_raises(encryptor):
    # Flip a byte inside the serialized KDF param block: it is part of the AAD,
    # so authentication must fail. (Byte 0 is algo_id; flip the iterations value.)
    blob = bytearray(encryptor.encrypt(b"secret", "pw"))
    param_len = len(kdfparams.serialize(PBKDF2KeyDerivation(iterations=1000).params()))
    blob[param_len - 1] ^= 0x01  # last byte of the iterations TLV value
    with pytest.raises(VaultError):
        encryptor.decrypt(bytes(blob), "pw")


def test_cross_kdf_decrypt_uses_stored_params(scrypt_encryptor):
    # A blob made with scrypt must decrypt even when handed to a PBKDF2-configured
    # encryptor instance, because decrypt rebuilds the KDF from the stored params.
    blob = scrypt_encryptor.encrypt(b"payload", "pw")
    other = AesGcmEncryptor(PBKDF2KeyDerivation(iterations=1000))
    assert other.decrypt(blob, "pw") == b"payload"


def test_unknown_algo_id_raises(encryptor):
    blob = bytearray(encryptor.encrypt(b"secret", "pw"))
    blob[0] = 0x7F  # bogus algo_id
    with pytest.raises(ContainerError):
        encryptor.decrypt(bytes(blob), "pw")


def test_crafted_zero_iterations_raises_vaulterror(encryptor):
    # Param layout: [algo, key_size, salt_size, tlv_count][tag, value]. Byte 3 is
    # tlv_count; the iterations value is the last 8 bytes of the 13-byte block.
    blob = bytearray(encryptor.encrypt(b"secret", "pw"))
    blob[5:13] = (0).to_bytes(8, "big")  # iterations = 0
    with pytest.raises(VaultError):  # ContainerError, NOT a Rust panic
        encryptor.decrypt(bytes(blob), "pw")


def test_crafted_bad_key_size_raises_vaulterror(encryptor):
    blob = bytearray(encryptor.encrypt(b"secret", "pw"))
    blob[1] = 10  # key_size = 10 (not a valid AES size)
    with pytest.raises(VaultError):  # ContainerError, NOT a bare ValueError
        encryptor.decrypt(bytes(blob), "pw")
