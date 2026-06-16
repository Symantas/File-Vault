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

Inspect a vault's format and KDF parameters (no password needed — this metadata
is stored and authenticated, not secret):

```bash
python main.py info my-project.vault
# version:    3
# kdf:        PBKDF2-HMAC-SHA256
# key size:   256-bit
# parameters: iterations=480000
```

Change a vault's password, optionally upgrading to the memory-hard scrypt KDF:

```bash
python main.py rekey my-project.vault            # prompts for old + new password
python main.py rekey my-project.vault --scrypt   # also upgrade the KDF
```

Useful flags:

```bash
python main.py encrypt secret.txt -o backup.vault   # choose output path
python main.py encrypt secret.txt --allow-weak       # bypass the weak-password check
python main.py decrypt backup.vault -d ./restore     # restore into a directory
python main.py decrypt backup.vault -f               # allow overwriting files
```

> A weak password (too short, or a known common password) is refused at encrypt
> and rekey time — the only real defense against offline brute force. Use
> `--allow-weak` to override.

> The `--password` flag is supported for scripting but is insecure because the
> password is visible in your shell history. Prefer the interactive prompt.

## Vault file format

```
container:  magic "FVLT" (4) | version 3 (1) | encrypted blob
blob:       kdf-param block | salt (16) | nonce (12) | ciphertext (+ 16-byte GCM tag)
plaintext:  a custom archive of the file/folder tree (names + contents)
```

The KDF parameter block makes each vault **self-describing**: it records the key
derivation algorithm and its work factor, so the key is always re-derived with
the parameters used at encryption time. The container header and this block are
authenticated as GCM associated data, so they cannot be tampered with or
downgraded. The original names and directory layout live *inside* the encrypted
payload, so they are never exposed on disk.

## Architecture

The library is organized around small, single-responsibility components that
depend on abstractions, so algorithms (KDF, cipher, archive format) can be
swapped or tested in isolation:

| Path                  | Responsibility                                          |
| --------------------- | ------------------------------------------------------- |
| `Vault/kdf.py`        | `KeyDerivation` interface + PBKDF2 and scrypt           |
| `Vault/kdfparams.py`  | KDF-parameter (de)serialization + algorithm registry    |
| `Vault/cipher.py`     | `Encryptor` interface + AES-256-GCM (composes a KDF)    |
| `Vault/archive.py`    | `Archiver` interface + safe file/folder (de)serializing |
| `Vault/container.py`  | `Container` interface + versioned header framing        |
| `Vault/strength.py`   | Password-strength heuristics (weak-password check)      |
| `Vault/service.py`    | `VaultService` orchestrator (`encrypt`/`decrypt`/`rekey`/`inspect`) |
| `Vault/errors.py`     | `VaultError` exception hierarchy                        |
| `Vault/cli.py`        | `argparse` command-line interface                       |
| `GUI/app.py`          | Graphical interface (planned)                           |
| `Tests/`              | `pytest` test suite                                     |
| `main.py`             | Entry point                                             |

`VaultService` wires the defaults together but accepts any `Encryptor`,
`Archiver`, or `Container`. For high-value data you can choose a memory-hard KDF
or a higher work factor — the choice is stored in the vault, so it always
decrypts correctly:

```python
from Vault import VaultService, AesGcmEncryptor, ScryptKeyDerivation

service = VaultService(encryptor=AesGcmEncryptor(ScryptKeyDerivation()))
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
