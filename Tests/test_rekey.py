import pytest

from Vault.cipher import AesGcmEncryptor
from Vault.errors import DecryptionError
from Vault.kdf import PBKDF2KeyDerivation, ScryptKeyDerivation
from Vault.service import VaultService


@pytest.fixture
def service():
    return VaultService(encryptor=AesGcmEncryptor(PBKDF2KeyDerivation(iterations=1000)))


def _vault(service, tmp_path):
    src = tmp_path / "f.txt"
    src.write_bytes(b"secret content")
    vault = service.encrypt_path(str(src), "old-pass")
    src.unlink()
    return vault


def test_rekey_changes_password_in_place(service, tmp_path):
    vault = _vault(service, tmp_path)
    out = service.rekey_path(vault, "old-pass", "new-pass")
    assert out == vault

    with pytest.raises(DecryptionError):
        service.decrypt_path(vault, "old-pass", str(tmp_path / "x"))

    service.decrypt_path(vault, "new-pass", str(tmp_path / "out"))
    assert (tmp_path / "out" / "f.txt").read_bytes() == b"secret content"


def test_rekey_wrong_old_password_leaves_file_untouched(service, tmp_path):
    vault = _vault(service, tmp_path)
    before = open(vault, "rb").read()
    with pytest.raises(DecryptionError):
        service.rekey_path(vault, "wrong", "new-pass")
    assert open(vault, "rb").read() == before


def test_rekey_can_upgrade_kdf(service, tmp_path):
    vault = _vault(service, tmp_path)
    assert service.inspect(vault).kdf_algorithm == "PBKDF2-HMAC-SHA256"

    scrypt = AesGcmEncryptor(ScryptKeyDerivation(n=2**8, r=8, p=1))
    service.rekey_path(vault, "old-pass", "new-pass", new_encryptor=scrypt)

    assert service.inspect(vault).kdf_algorithm == "scrypt"
    service.decrypt_path(vault, "new-pass", str(tmp_path / "out"))
    assert (tmp_path / "out" / "f.txt").read_bytes() == b"secret content"


def test_cli_rekey_changes_password(service, tmp_path):
    from Vault.cli import main

    vault = _vault(service, tmp_path)
    rc = main(["--password", "old-pass", "rekey", vault, "--new-password", "new-pass"])
    assert rc == 0

    service.decrypt_path(vault, "new-pass", str(tmp_path / "out"))
    assert (tmp_path / "out" / "f.txt").read_bytes() == b"secret content"


def test_cli_rekey_wrong_old_password_errors(service, tmp_path, capsys):
    from Vault.cli import main

    vault = _vault(service, tmp_path)
    rc = main(["--password", "wrong", "rekey", vault, "--new-password", "new-pass"])
    assert rc == 1
    assert "error" in capsys.readouterr().err.lower()
