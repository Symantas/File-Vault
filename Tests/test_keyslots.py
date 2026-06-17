import pytest

from Vault.errors import DecryptionError, SlotError
from Vault.kdf import PBKDF2KeyDerivation
from Vault.service import VaultService

A = "first strong passphrase"
B = "second strong passphrase"
C = "third strong passphrase"


@pytest.fixture
def service():
    return VaultService(default_kdf=PBKDF2KeyDerivation(iterations=1000))


def _vault(service, tmp_path, *passwords):
    src = tmp_path / "f.txt"
    src.write_bytes(b"shared secret")
    vault = service.encrypt_path(str(src), passwords=passwords)
    src.unlink()
    return vault


def _payload(path):
    """Return the encrypted payload bytes (everything after the slot section)."""
    import struct
    from Vault import slotcodec
    with open(path, "rb") as fh:
        fh.read(5)  # header
        slotcodec.read_section(fh)
        return fh.read()  # chunk_size + chunks


def test_two_passwords_both_unlock(service, tmp_path):
    vault = _vault(service, tmp_path, A, B)
    assert len(service.inspect(vault).slots) == 2
    for pw, sub in ((A, "a"), (B, "b")):
        out = tmp_path / sub
        service.decrypt_path(vault, password=pw, destination_dir=str(out))
        assert (out / "f.txt").read_bytes() == b"shared secret"


def test_add_password_then_both_work(service, tmp_path):
    vault = _vault(service, tmp_path, A)
    service.add_password(vault, new_password=B, unlock_password=A)
    assert len(service.inspect(vault).slots) == 2
    for pw, sub in ((A, "a"), (B, "b")):
        service.decrypt_path(vault, password=pw, destination_dir=str(tmp_path / sub))
        assert (tmp_path / sub / "f.txt").read_bytes() == b"shared secret"


def test_remove_slot(service, tmp_path):
    vault = _vault(service, tmp_path, A, B)
    service.remove_slot(vault, index=0)  # remove the A slot
    assert len(service.inspect(vault).slots) == 1
    with pytest.raises(DecryptionError):
        service.decrypt_path(vault, password=A, destination_dir=str(tmp_path / "x"))
    service.decrypt_path(vault, password=B, destination_dir=str(tmp_path / "b"))
    assert (tmp_path / "b" / "f.txt").read_bytes() == b"shared secret"


def test_cannot_remove_last_slot(service, tmp_path):
    vault = _vault(service, tmp_path, A)
    with pytest.raises(SlotError):
        service.remove_slot(vault, index=0)


def test_remove_bad_index(service, tmp_path):
    vault = _vault(service, tmp_path, A, B)
    with pytest.raises(SlotError):
        service.remove_slot(vault, index=9)


def test_wrong_password_tries_all_slots(service, tmp_path):
    vault = _vault(service, tmp_path, A, B)
    with pytest.raises(DecryptionError):
        service.decrypt_path(vault, password="nope-nope-nope", destination_dir=str(tmp_path / "x"))


def test_add_remove_does_not_reencrypt_payload(service, tmp_path):
    # O(1) property: only the slot section changes; the payload is byte-identical.
    vault = _vault(service, tmp_path, A)
    before = _payload(vault)
    service.add_password(vault, new_password=B, unlock_password=A)
    assert _payload(vault) == before
    service.remove_slot(vault, index=0)
    assert _payload(vault) == before
