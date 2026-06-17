import pytest

from Vault.identity import Identity
from Vault.errors import DecryptionError
from Vault.kdf import PBKDF2KeyDerivation
from Vault.service import VaultService

PW = "a strong passphrase"


@pytest.fixture
def service():
    return VaultService(default_kdf=PBKDF2KeyDerivation(iterations=1000))


def _src(tmp_path):
    src = tmp_path / "f.txt"
    src.write_bytes(b"recipient secret")
    return src


def test_recipient_round_trip(service, tmp_path):
    identity = Identity.generate()
    src = _src(tmp_path)
    vault = service.encrypt_path(str(src), recipients=(identity.recipient(),))
    src.unlink()

    assert service.inspect(vault).slots[0].type == "x25519"
    service.decrypt_path(vault, identity=identity, destination_dir=str(tmp_path / "out"))
    assert (tmp_path / "out" / "f.txt").read_bytes() == b"recipient secret"


def test_wrong_identity_fails(service, tmp_path):
    src = _src(tmp_path)
    vault = service.encrypt_path(str(src), recipients=(Identity.generate().recipient(),))
    with pytest.raises(DecryptionError):
        service.decrypt_path(vault, identity=Identity.generate(), destination_dir=str(tmp_path / "x"))


def test_multiple_recipients_each_unlock(service, tmp_path):
    alice, bob = Identity.generate(), Identity.generate()
    src = _src(tmp_path)
    vault = service.encrypt_path(str(src), recipients=(alice.recipient(), bob.recipient()))
    src.unlink()
    for ident, sub in ((alice, "a"), (bob, "b")):
        service.decrypt_path(vault, identity=ident, destination_dir=str(tmp_path / sub))
        assert (tmp_path / sub / "f.txt").read_bytes() == b"recipient secret"


def test_mixed_password_and_recipient_vault(service, tmp_path):
    identity = Identity.generate()
    src = _src(tmp_path)
    vault = service.encrypt_path(str(src), passwords=(PW,), recipients=(identity.recipient(),))
    src.unlink()
    service.decrypt_path(vault, password=PW, destination_dir=str(tmp_path / "p"))
    service.decrypt_path(vault, identity=identity, destination_dir=str(tmp_path / "i"))
    assert (tmp_path / "p" / "f.txt").read_bytes() == b"recipient secret"
    assert (tmp_path / "i" / "f.txt").read_bytes() == b"recipient secret"


def test_add_recipient_to_password_vault(service, tmp_path):
    identity = Identity.generate()
    src = _src(tmp_path)
    vault = service.encrypt_path(str(src), passwords=(PW,))
    src.unlink()
    service.add_recipient(vault, recipient=identity.recipient(), unlock_password=PW)
    service.decrypt_path(vault, identity=identity, destination_dir=str(tmp_path / "out"))
    assert (tmp_path / "out" / "f.txt").read_bytes() == b"recipient secret"


def test_hkdf_salt_binding_blocks_other_identity(service, tmp_path):
    # A slot built for alice must not be unlockable by bob even though both are
    # valid X25519 identities (the recipient pubkey is bound into the KDF salt).
    alice, bob = Identity.generate(), Identity.generate()
    src = _src(tmp_path)
    vault = service.encrypt_path(str(src), recipients=(alice.recipient(),))
    with pytest.raises(DecryptionError):
        service.decrypt_path(vault, identity=bob, destination_dir=str(tmp_path / "x"))
