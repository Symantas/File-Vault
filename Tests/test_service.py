import os

import pytest

from Vault.cipher import AesGcmEncryptor
from Vault.errors import DecryptionError, OverwriteError
from Vault.kdf import PBKDF2KeyDerivation
from Vault.service import VaultService


@pytest.fixture
def service():
    # Fast KDF for tests; everything else is the default wiring.
    return VaultService(encryptor=AesGcmEncryptor(PBKDF2KeyDerivation(iterations=1000)))


def test_file_round_trip(service, tmp_path):
    src = tmp_path / "secret.txt"
    content = b"top secret\n"
    src.write_bytes(content)

    container = service.encrypt_path(str(src), "pw")
    assert container == str(src) + ".vault"
    # Ciphertext must not contain the plaintext.
    assert content not in open(container, "rb").read()

    src.unlink()
    written = service.decrypt_path(container, "pw")
    assert written == [str(tmp_path / "secret.txt")]
    assert (tmp_path / "secret.txt").read_bytes() == content


def test_folder_round_trip(service, tmp_path):
    root = tmp_path / "docs"
    (root / "nested").mkdir(parents=True)
    (root / "a.txt").write_bytes(b"AAA")
    (root / "nested" / "b.bin").write_bytes(b"\x00\xff")

    container = service.encrypt_path(str(root), "pw")
    assert container == str(root) + ".vault"

    out = tmp_path / "restored"
    service.decrypt_path(container, "pw", str(out))
    assert (out / "docs" / "a.txt").read_bytes() == b"AAA"
    assert (out / "docs" / "nested" / "b.bin").read_bytes() == b"\x00\xff"


def test_wrong_password_raises(service, tmp_path):
    src = tmp_path / "f.txt"
    src.write_bytes(b"hi")
    container = service.encrypt_path(str(src), "right")
    with pytest.raises(DecryptionError):
        service.decrypt_path(container, "wrong", str(tmp_path / "out"))


def test_container_has_owner_only_permissions(service, tmp_path):
    src = tmp_path / "f.txt"
    src.write_bytes(b"hi")
    container = service.encrypt_path(str(src), "pw")
    mode = os.stat(container).st_mode & 0o777
    assert mode == 0o600


def test_decrypt_respects_overwrite_flag(service, tmp_path):
    src = tmp_path / "f.txt"
    src.write_bytes(b"v2")
    container = service.encrypt_path(str(src), "pw")

    # Original still present -> decrypt back into tmp_path should refuse.
    with pytest.raises(OverwriteError):
        service.decrypt_path(container, "pw")
    service.decrypt_path(container, "pw", overwrite=True)
