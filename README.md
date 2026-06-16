# File-Vault

A small command-line tool for encrypting and decrypting **files and folders**
with a password.

Data is protected with **AES-256-GCM** (authenticated encryption). The key is
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

Encrypt a **file** (you will be prompted for a password):

```bash
python main.py encrypt secret.txt
# -> writes secret.txt.vault
```

Encrypt a whole **folder** — the entire tree is archived into one container:

```bash
python main.py encrypt my-project
# -> writes my-project.vault
```

Decrypt again (original names and folder structure are restored automatically):

```bash
python main.py decrypt my-project.vault
# restores ./my-project/...
```

Useful flags:

```bash
python main.py encrypt secret.txt -o backup.vault   # choose output path
python main.py decrypt backup.vault -d ./restore     # restore into a directory
python main.py decrypt backup.vault -f               # allow overwriting files
```

> The `--password` flag is supported for scripting but is insecure because the
> password is visible in your shell history. Prefer the interactive prompt.

## Vault file format

```
container:  magic "FVLT" (4) | version (1) | encrypted blob
blob:       salt (16) | nonce (12) | ciphertext (+ 16-byte GCM tag)
plaintext:  a custom archive of the file/folder tree (names + contents)
```

The original names and directory layout live *inside* the encrypted payload, so
they are never exposed on disk.

## Architecture

The library is organized around small, single-responsibility components that
depend on abstractions, so algorithms (KDF, cipher, archive format) can be
swapped or tested in isolation:

| Path                  | Responsibility                                          |
| --------------------- | ------------------------------------------------------- |
| `Vault/kdf.py`        | `KeyDerivation` interface + PBKDF2 implementation       |
| `Vault/cipher.py`     | `Encryptor` interface + AES-256-GCM (composes a KDF)    |
| `Vault/archive.py`    | `Archiver` interface + safe file/folder (de)serializing |
| `Vault/container.py`  | Versioned vault header framing                          |
| `Vault/service.py`    | `VaultService` orchestrator (dependency-injected)       |
| `Vault/errors.py`     | `VaultError` exception hierarchy                        |
| `Vault/cli.py`        | `argparse` command-line interface                       |
| `GUI/app.py`          | Graphical interface (planned)                           |
| `Tests/`              | `pytest` test suite                                     |
| `main.py`             | Entry point                                             |

`VaultService` wires the defaults together but accepts any `Encryptor`,
`Archiver`, or `VaultContainer`, e.g.:

```python
from Vault import VaultService, AesGcmEncryptor, PBKDF2KeyDerivation

service = VaultService(encryptor=AesGcmEncryptor(PBKDF2KeyDerivation(iterations=600_000)))
service.encrypt_path("my-folder", "password")
```

## Security

See [SECURITY.md](SECURITY.md) for the threat model, hardening measures
(authenticated encryption, path-traversal protection, symlink handling,
restrictive file permissions), and known limitations.

## Running the tests

```bash
pip install pytest
python -m pytest
```
