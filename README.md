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

### Sharing with public-key recipients

Generate an identity (private key file) and share the printed recipient string:

```bash
python main.py keygen -o my-identity.key
# Recipient: agevault-pub-OWtNv2bpWBg1_7jyaoUCWD...
```

Encrypt *to* one or more recipients — no shared password needed — and let the
holder of the matching identity decrypt:

```bash
python main.py encrypt report.pdf --recipient agevault-pub-...
python main.py decrypt report.pdf.vault --identity my-identity.key
```

### Managing who can open a vault

A vault can have several key slots (passwords and/or recipients); any one opens
it, and adding or removing a slot never re-encrypts the data:

```bash
python main.py add-password  my.vault                       # add another password
python main.py add-recipient my.vault --recipient agevault-pub-... --identity my-identity.key
python main.py info          my.vault                       # list slots
python main.py remove-slot   my.vault --index 0             # revoke a slot
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

## Vault file format (v4)

```
header:   magic "FVLT" (4) | version 4 (1)
slots:    slot_count (1) | per slot: type (1) | body_len (2) | body
          (a key slot wraps the random Data Encryption Key under one secret)
payload:  chunk_size (4) | repeated [ chunk_len (4) | AES-256-GCM chunk+tag ]
```

A random **Data Encryption Key (DEK)** encrypts the payload once, as a sequence
of authenticated chunks (the STREAM construction), so arbitrarily large
files/folders are processed with constant memory. Each **key slot** stores the
DEK wrapped under a different secret (a password's derived key; public-key
recipients are coming), which is what enables multiple unlock methods and O(1)
re-keying. The container header and chunk size are authenticated as GCM
associated data (anti-downgrade), and each chunk's counter + final-flag detect
reordering, truncation, and tampering. Names and directory layout live *inside*
the encrypted payload, never on disk. A KDF parameter block stored in each
password slot makes the work factor self-describing and upgradable.

## Architecture

The library is organized around small, single-responsibility components that
depend on abstractions, so algorithms (KDF, cipher, archive format) can be
swapped or tested in isolation:

| Path                  | Responsibility                                          |
| --------------------- | ------------------------------------------------------- |
| `Vault/kdf.py`        | `KeyDerivation` interface + PBKDF2 and scrypt           |
| `Vault/kdfparams.py`  | KDF-parameter (de)serialization + algorithm registry    |
| `Vault/stream.py`     | `ChunkStreamEncryptor` — chunked AES-256-GCM (STREAM)   |
| `Vault/slots.py`      | `KeySlot` interface + `PasswordSlot` / `RecipientSlot`   |
| `Vault/slotcodec.py`  | Key-slot section framing                                 |
| `Vault/identity.py`   | X25519 `Identity` / `Recipient` keys                    |
| `Vault/cipher.py`     | `Encryptor` interface + AES-256-GCM (single-shot)       |
| `Vault/archive.py`    | `Archiver` interface + safe streaming (de)serializing   |
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
