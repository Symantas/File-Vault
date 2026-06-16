# File-Vault

A small command-line tool for encrypting and decrypting files with a password.

Files are protected with **AES-256-GCM** (authenticated encryption). The key is
derived from your password using **PBKDF2-HMAC-SHA256** with a random salt, so
the same password produces a different ciphertext every time and any tampering
with an encrypted file is detected on decryption.

## Installation

```bash
pip install -r requirements.txt
```

`cryptography` is required. `customTkinter` is only needed for the (work in
progress) graphical interface.

## Usage

Encrypt a file (you will be prompted for a password):

```bash
python main.py encrypt secret.txt
# -> writes secret.txt.vault
```

Decrypt it again (the original file name is restored automatically):

```bash
python main.py decrypt secret.txt.vault
# -> writes secret.txt
```

Choose an explicit output path with `-o`:

```bash
python main.py encrypt secret.txt -o backup.vault
python main.py decrypt backup.vault -o restored.txt
```

> The `--password` flag is supported for scripting but is insecure because the
> password is visible in your shell history. Prefer the interactive prompt.

## Vault file format

```
magic "FVLT" (4 bytes) | version (1 byte) | salt (16) | nonce (12) | ciphertext+tag
```

The original file name is stored *inside* the encrypted payload, so it is never
exposed on disk.

## Project layout

| Path                  | Purpose                                            |
| --------------------- | -------------------------------------------------- |
| `Vault/encryption.py` | AES-256-GCM encryption and PBKDF2 key derivation   |
| `Vault/packer.py`     | Vault container header and payload (de)serializing |
| `Vault/vault.py`      | High-level encrypt/decrypt-file helpers            |
| `Vault/cli.py`        | `argparse` command-line interface                  |
| `GUI/app.py`          | Graphical interface (planned)                      |
| `Tests/`              | `pytest` test suite                                |
| `main.py`             | Entry point                                        |

## Running the tests

```bash
pip install pytest
python -m pytest
```
