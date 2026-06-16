import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Vault import vault  # noqa: E402
from Vault.encryption import DecryptionError  # noqa: E402


def test_encrypt_decrypt_file_round_trip(tmp_path):
    src = tmp_path / "secret.txt"
    content = b"top secret contents\n"
    src.write_bytes(content)

    container = vault.encrypt_file(str(src), "pw")
    assert container == str(src) + vault.VAULT_SUFFIX
    assert os.path.exists(container)
    # The ciphertext on disk must not contain the plaintext.
    assert content not in open(container, "rb").read()

    src.unlink()  # remove original to prove restoration
    out = vault.decrypt_file(container, "pw")
    assert os.path.basename(out) == "secret.txt"
    assert open(out, "rb").read() == content


def test_decrypt_with_explicit_output(tmp_path):
    src = tmp_path / "data.bin"
    src.write_bytes(b"\x00\xff\x10")
    container = vault.encrypt_file(str(src), "pw")

    dest = tmp_path / "restored.bin"
    vault.decrypt_file(container, "pw", str(dest))
    assert dest.read_bytes() == b"\x00\xff\x10"


def test_decrypt_wrong_password_raises(tmp_path):
    src = tmp_path / "f.txt"
    src.write_bytes(b"hi")
    container = vault.encrypt_file(str(src), "right")
    with pytest.raises(DecryptionError):
        vault.decrypt_file(container, "wrong")
