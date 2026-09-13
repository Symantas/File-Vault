import struct

import pytest

from Vault import kdfparams
from Vault.errors import ContainerError
from Vault.kdf import PBKDF2KeyDerivation, ScryptKeyDerivation


def test_pbkdf2_round_trip():
    params = PBKDF2KeyDerivation(iterations=12345, key_size=32, salt_size=16).params()
    parsed, consumed = kdfparams.deserialize(kdfparams.serialize(params))
    assert parsed == params
    assert consumed == len(kdfparams.serialize(params))


def test_scrypt_round_trip():
    params = ScryptKeyDerivation(n=2**10, r=8, p=2).params()
    parsed, consumed = kdfparams.deserialize(kdfparams.serialize(params))
    assert parsed == params
    assert consumed == len(kdfparams.serialize(params))


def test_factory_rebuilds_equivalent_kdf():
    original = ScryptKeyDerivation(n=2**8, r=8, p=1)
    parsed, _ = kdfparams.deserialize(kdfparams.serialize(original.params()))
    rebuilt = kdfparams.kdf_from_params(parsed)
    salt = b"0123456789abcdef"
    assert rebuilt.derive("pw", salt) == original.derive("pw", salt)


def test_deserialize_leaves_trailing_bytes():
    params = PBKDF2KeyDerivation(iterations=1000).params()
    blob = kdfparams.serialize(params) + b"TRAILING"
    parsed, consumed = kdfparams.deserialize(blob)
    assert parsed == params
    assert blob[consumed:] == b"TRAILING"


def test_unknown_algo_id_raises():
    with pytest.raises(ContainerError):
        kdfparams.deserialize(struct.pack(">BBBB", 0x7F, 32, 16, 0))


def test_unknown_tag_raises():
    # algo PBKDF2, 1 TLV with a bogus tag.
    blob = struct.pack(">BBBB", 1, 32, 16, 1) + struct.pack(">BQ", 0x99, 1000)
    with pytest.raises(ContainerError):
        kdfparams.deserialize(blob)


def test_missing_required_param_raises():
    # algo PBKDF2 but zero TLVs -> iterations missing.
    blob = struct.pack(">BBBB", 1, 32, 16, 0)
    with pytest.raises(ContainerError):
        kdfparams.deserialize(blob)


def test_truncated_block_raises():
    params = PBKDF2KeyDerivation(iterations=1000).params()
    full = kdfparams.serialize(params)
    with pytest.raises(ContainerError):
        kdfparams.deserialize(full[:-3])  # cut into the TLV value


def test_serialize_unknown_algo_raises():
    from Vault.kdf import KdfParams

    with pytest.raises(ContainerError):
        kdfparams.serialize(KdfParams(0x7F, 32, 16, {}))


def test_zero_iterations_rejected():
    # Would otherwise reach the crypto backend and raise a Rust PanicException.
    blob = struct.pack(">BBBB", 1, 32, 16, 1) + struct.pack(">BQ", 0x01, 0)
    with pytest.raises(ContainerError):
        kdfparams.deserialize(blob)


def test_zero_salt_size_rejected():
    blob = struct.pack(">BBBB", 1, 0, 16, 1) + struct.pack(">BQ", 0x01, 1000)
    with pytest.raises(ContainerError):
        kdfparams.deserialize(blob)


def test_non_power_of_two_scrypt_n_rejected():
    body = struct.pack(">BQ", 0x10, 3) + struct.pack(">BQ", 0x11, 8) + struct.pack(">BQ", 0x12, 1)
    blob = struct.pack(">BBBB", 2, 32, 16, 3) + body
    with pytest.raises(ContainerError):
        kdfparams.deserialize(blob)


def test_zero_scrypt_r_or_p_rejected():
    body = struct.pack(">BQ", 0x10, 2**10) + struct.pack(">BQ", 0x11, 0) + struct.pack(">BQ", 0x12, 1)
    blob = struct.pack(">BBBB", 2, 32, 16, 3) + body
    with pytest.raises(ContainerError):
        kdfparams.deserialize(blob)
