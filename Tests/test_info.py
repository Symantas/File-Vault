import pytest

from Vault.cipher import AesGcmEncryptor
from Vault.errors import ContainerError
from Vault.kdf import PBKDF2KeyDerivation, ScryptKeyDerivation
from Vault.service import VaultInfo, VaultService


@pytest.fixture
def pbkdf2_service():
    return VaultService(encryptor=AesGcmEncryptor(PBKDF2KeyDerivation(iterations=1000)))


def _make_vault(service, tmp_path, name="f.txt"):
    src = tmp_path / name
    src.write_bytes(b"data")
    return service.encrypt_path(str(src), "pw")


def test_inspect_reports_pbkdf2_metadata(pbkdf2_service, tmp_path):
    info = pbkdf2_service.inspect(_make_vault(pbkdf2_service, tmp_path))
    assert isinstance(info, VaultInfo)
    assert info.version == 3
    assert info.kdf_algorithm == "PBKDF2-HMAC-SHA256"
    assert info.parameters["iterations"] == 1000
    assert info.key_size == 32


def test_inspect_reports_scrypt_metadata(tmp_path):
    svc = VaultService(encryptor=AesGcmEncryptor(ScryptKeyDerivation(n=2**8, r=8, p=1)))
    info = svc.inspect(_make_vault(svc, tmp_path))
    assert info.kdf_algorithm == "scrypt"
    assert info.parameters == {"n": 2**8, "r": 8, "p": 1}


def test_inspect_needs_no_password(pbkdf2_service, tmp_path):
    # The whole point: metadata is readable without decrypting.
    vault = _make_vault(pbkdf2_service, tmp_path)
    assert pbkdf2_service.inspect(vault).kdf_algorithm  # no password argument


def test_inspect_rejects_non_vault(pbkdf2_service, tmp_path):
    bogus = tmp_path / "bogus.bin"
    bogus.write_bytes(b"not a vault at all")
    with pytest.raises(ContainerError):
        pbkdf2_service.inspect(str(bogus))


def test_cli_info_prints_metadata(pbkdf2_service, tmp_path, capsys):
    from Vault.cli import main

    vault = _make_vault(pbkdf2_service, tmp_path)
    rc = main(["info", vault])
    out = capsys.readouterr().out
    assert rc == 0
    assert "PBKDF2-HMAC-SHA256" in out
    assert "iterations" in out
    assert "version" in out.lower()


def test_cli_info_on_bad_file_returns_error(tmp_path, capsys):
    from Vault.cli import main

    bogus = tmp_path / "bad.bin"
    bogus.write_bytes(b"nope")
    rc = main(["info", str(bogus)])
    assert rc == 1
    assert "error" in capsys.readouterr().err.lower()
