import pytest

from Vault.errors import ContainerError
from Vault.kdf import PBKDF2KeyDerivation, ScryptKeyDerivation
from Vault.service import VaultInfo, VaultService


@pytest.fixture
def service():
    return VaultService(default_kdf=PBKDF2KeyDerivation(iterations=1000))


def _make_vault(service, tmp_path, name="f.txt"):
    src = tmp_path / name
    src.write_bytes(b"data")
    return service.encrypt_path(str(src), passwords=("a strong passphrase",))


def test_inspect_reports_version_and_password_slot(service, tmp_path):
    info = service.inspect(_make_vault(service, tmp_path))
    assert isinstance(info, VaultInfo)
    assert info.version == 4
    assert len(info.slots) == 1
    slot = info.slots[0]
    assert slot.type == "password"
    assert slot.kdf_algorithm == "PBKDF2-HMAC-SHA256"
    assert slot.parameters["iterations"] == 1000


def test_inspect_reports_scrypt_slot(tmp_path):
    svc = VaultService(default_kdf=ScryptKeyDerivation(n=2**8, r=8, p=1))
    info = svc.inspect(_make_vault(svc, tmp_path))
    assert info.slots[0].type == "password"
    assert info.slots[0].kdf_algorithm == "scrypt"
    assert info.slots[0].parameters == {"n": 2**8, "r": 8, "p": 1}


def test_inspect_needs_no_password(service, tmp_path):
    vault = _make_vault(service, tmp_path)
    assert service.inspect(vault).slots  # no password argument


def test_inspect_rejects_non_vault(service, tmp_path):
    bogus = tmp_path / "bogus.bin"
    bogus.write_bytes(b"not a vault at all")
    with pytest.raises(ContainerError):
        service.inspect(str(bogus))


def test_cli_info_prints_metadata(service, tmp_path, capsys):
    from Vault.cli import main

    vault = _make_vault(service, tmp_path)
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
