from Vault import strength


def test_empty_password_is_weak():
    assert strength.weaknesses("") != []


def test_short_password_is_weak():
    assert any("short" in r.lower() for r in strength.weaknesses("ab12"))


def test_common_password_is_weak():
    assert any("common" in r.lower() for r in strength.weaknesses("password"))


def test_common_check_is_case_insensitive():
    assert any("common" in r.lower() for r in strength.weaknesses("PassWord"))


def test_strong_passphrase_has_no_weaknesses():
    assert strength.weaknesses("correct horse battery staple") == []


def test_is_acceptable_matches_weaknesses():
    assert strength.is_acceptable("correct horse battery staple") is True
    assert strength.is_acceptable("123456") is False


def test_cli_encrypt_blocks_weak_password(tmp_path, capsys):
    from Vault.cli import main

    src = tmp_path / "f.txt"
    src.write_bytes(b"x")
    rc = main(["--password", "123456", "encrypt", str(src)])
    assert rc == 1
    assert "weak" in capsys.readouterr().err.lower()
    assert not (tmp_path / "f.txt.vault").exists()  # nothing was written


def test_cli_encrypt_allows_weak_with_flag(tmp_path):
    from Vault.cli import main

    src = tmp_path / "f.txt"
    src.write_bytes(b"x")
    rc = main(["--password", "123456", "encrypt", str(src), "--allow-weak"])
    assert rc == 0
    assert (tmp_path / "f.txt.vault").exists()


def test_cli_encrypt_accepts_strong_password(tmp_path):
    from Vault.cli import main

    src = tmp_path / "f.txt"
    src.write_bytes(b"x")
    rc = main(["--password", "correct horse battery staple", "encrypt", str(src)])
    assert rc == 0
    assert (tmp_path / "f.txt.vault").exists()
