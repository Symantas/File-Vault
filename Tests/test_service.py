import os

import pytest

from Vault.errors import DecryptionError, OverwriteError
from Vault.kdf import PBKDF2KeyDerivation, ScryptKeyDerivation
from Vault.service import VaultService

PW = "a strong passphrase"


@pytest.fixture
def service():
    return VaultService(default_kdf=PBKDF2KeyDerivation(iterations=1000))


def test_file_round_trip(service, tmp_path):
    src = tmp_path / "secret.txt"
    content = b"top secret\n"
    src.write_bytes(content)

    container = service.encrypt_path(str(src), passwords=(PW,))
    assert container == str(src) + ".vault"
    assert content not in open(container, "rb").read()  # not in cleartext

    src.unlink()
    written = service.decrypt_path(container, password=PW)
    assert written == [str(tmp_path / "secret.txt")]
    assert (tmp_path / "secret.txt").read_bytes() == content


def test_folder_round_trip(service, tmp_path):
    root = tmp_path / "docs"
    (root / "nested").mkdir(parents=True)
    (root / "a.txt").write_bytes(b"AAA")
    (root / "nested" / "b.bin").write_bytes(b"\x00\xff")

    container = service.encrypt_path(str(root), passwords=(PW,))
    out = tmp_path / "restored"
    service.decrypt_path(container, password=PW, destination_dir=str(out))
    assert (out / "docs" / "a.txt").read_bytes() == b"AAA"
    assert (out / "docs" / "nested" / "b.bin").read_bytes() == b"\x00\xff"


def test_large_multichunk_round_trip(service, tmp_path):
    # Bigger than the 64 KiB chunk size: exercises the streaming path.
    src = tmp_path / "big.bin"
    blob = os.urandom(300 * 1024)
    src.write_bytes(blob)
    container = service.encrypt_path(str(src), passwords=(PW,))
    src.unlink()
    service.decrypt_path(container, password=PW)
    assert (tmp_path / "big.bin").read_bytes() == blob


def test_wrong_password_raises(service, tmp_path):
    src = tmp_path / "f.txt"
    src.write_bytes(b"hi")
    container = service.encrypt_path(str(src), passwords=("right-passphrase",))
    with pytest.raises(DecryptionError):
        service.decrypt_path(container, password="wrong", destination_dir=str(tmp_path / "out"))


def test_no_secret_rejected(service, tmp_path):
    src = tmp_path / "f.txt"
    src.write_bytes(b"hi")
    with pytest.raises(ValueError):
        service.encrypt_path(str(src))


def test_container_has_owner_only_permissions(service, tmp_path):
    src = tmp_path / "f.txt"
    src.write_bytes(b"hi")
    container = service.encrypt_path(str(src), passwords=(PW,))
    assert os.stat(container).st_mode & 0o777 == 0o600


def test_decrypt_respects_overwrite_flag(service, tmp_path):
    src = tmp_path / "f.txt"
    src.write_bytes(b"v2")
    container = service.encrypt_path(str(src), passwords=(PW,))

    with pytest.raises(OverwriteError):
        service.decrypt_path(container, password=PW)  # original still present
    service.decrypt_path(container, password=PW, overwrite=True)


def test_scrypt_backed_round_trip(tmp_path):
    svc = VaultService(default_kdf=ScryptKeyDerivation(n=2**8, r=8, p=1))
    src = tmp_path / "s.txt"
    src.write_bytes(b"memory-hard")
    container = svc.encrypt_path(str(src), passwords=(PW,))
    src.unlink()
    svc.decrypt_path(container, password=PW)
    assert (tmp_path / "s.txt").read_bytes() == b"memory-hard"


def test_truncated_payload_leaves_no_partial_output(service, tmp_path):
    src = tmp_path / "big.bin"
    src.write_bytes(os.urandom(200 * 1024))
    container = service.encrypt_path(str(src), passwords=(PW,))
    src.unlink()

    # Chop off the last 32 bytes of the payload -> truncated stream.
    raw = bytearray(open(container, "rb").read())
    open(container, "wb").write(bytes(raw[:-32]))

    out = tmp_path / "out"
    with pytest.raises(DecryptionError):
        service.decrypt_path(container, password=PW, destination_dir=str(out))
    # Staging means nothing was written to the destination.
    assert not (out / "big.bin").exists()
