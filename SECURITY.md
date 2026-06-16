# Security Notes

This document describes File-Vault's threat model, the hardening measures in
place, and known limitations. It reflects the state of the code as of the
current revision.

## Cryptographic design

| Concern              | Choice                                                              |
| -------------------- | ------------------------------------------------------------------ |
| Confidentiality      | AES-256-GCM                                                         |
| Integrity / tamper   | GCM authentication tag (AEAD) — decryption fails on changes        |
| Key derivation       | PBKDF2-HMAC-SHA256 (480k iters, default) or memory-hard scrypt      |
| KDF parameters       | Stored in the vault and authenticated — self-describing, upgradable |
| Salt                 | 16 random bytes per encryption (`os.urandom`)                      |
| Nonce                | 12 random bytes per encryption (`os.urandom`)                      |

**Self-describing, upgradable KDF.** Each vault stores the KDF algorithm and its
parameters (e.g. PBKDF2 iteration count, or scrypt `n`/`r`/`p`) in a small block
that is decoded on decryption. The key is always re-derived with the parameters
the vault was created with, so the default work factor can be raised over time —
the standard defense against offline brute force — *without* making existing
vaults undecryptable. A memory-hard `ScryptKeyDerivation` is available (no extra
dependency) for stronger resistance to GPU/ASIC cracking.

**Authenticated metadata.** The container header (magic + version) and the KDF
parameter block are passed to AES-GCM as associated data (AAD), so they are
authenticated. An attacker cannot tamper with them or downgrade the algorithm /
iteration count without failing decryption.

**Nonce-reuse safety.** GCM is catastrophically weak if a (key, nonce) pair is
ever reused. File-Vault draws a *fresh random salt* on every encryption, which
produces a *fresh key* every time, so even if a 96-bit nonce ever repeated it
would be under a different key. Reuse is therefore not a practical risk.

**No encryption oracle.** A wrong password and corrupted data both surface the
same generic `DecryptionError` (the library raises `InvalidTag` in both cases),
so decryption does not leak whether the password was close or the data was
modified.

## Threats addressed

- **Path traversal / "Zip Slip" (CWE-22).** When extracting an archive, every
  entry path is validated: absolute paths, `..` components, `.` components,
  empty components, and backslashes are rejected, and the fully resolved target
  is verified to stay within the destination directory (`Archive._safe_target`).
  This is covered by parametrized tests with hostile, hand-crafted archives.
- **Symlink-based exfiltration / loops when reading.** Archiving refuses a
  symlinked source, walks with `followlinks=False`, and skips symlinked files
  and directories rather than following them out of the tree.
- **Symlink-based escape when writing.** Extraction never creates symlinks, and
  the resolved-path containment check rejects writes that would escape through a
  pre-existing symlinked parent directory.
- **Accidental overwrite.** Extraction refuses to overwrite existing files
  unless `--force` is passed.
- **Decryption / archive bombs.** No compression is used, so there is no
  amplification factor. The archive reader bounds every read against the actual
  remaining bytes, so a malformed length field cannot trigger an oversized
  allocation — it raises `ArchiveError` instead.
- **At-rest exposure of vault files.** Vault containers are created with
  `0600` (owner read/write only) permissions.
- **Symlink clobber of the output path.** The vault file is opened with
  `O_NOFOLLOW`, so a symlink planted at the output path is refused rather than
  followed (which would otherwise truncate the link's target).
- **Metadata tampering / KDF downgrade.** The container header and KDF parameter
  block are authenticated as AAD, so an attacker cannot alter the version or
  weaken the stored work factor without failing decryption.
- **Plaintext file names on disk.** Names and the directory layout are stored
  *inside* the encrypted payload, never in the clear.

## Residual risk: offline brute force

A vault file is self-contained — it carries the salt, nonce, KDF parameters, and
ciphertext+tag. Anyone who obtains the file can therefore guess passwords
entirely **offline**; a correct guess is recognized when GCM authentication
succeeds. This is inherent to password-based encryption and is demonstrated by
`Tests/test_bruteforce_poc.py`.

The only defense is password strength and the KDF work factor:

- **Use a strong, unique passphrase.** A weak or wordlist password falls quickly
  regardless of the KDF.
- **Raise the work factor or use scrypt** for high-value data. Because the KDF
  parameters are stored per vault, the default can be increased over time without
  breaking older vaults.

## Known limitations

These are documented trade-offs, not silent gaps:

1. **In-memory processing.** Files/folders are read fully into memory before
   encryption and after decryption. Extremely large inputs can exhaust RAM.
   Streaming/chunked encryption is future work.
2. **Password material in memory.** Python `str`/`bytes` are immutable and cannot
   be reliably zeroed, so the password and derived key may linger in memory until
   garbage collected. (Reviewed: no secrets are written to logs, errors, temp
   files, environment variables, or any registry.)
3. **`--password` flag.** Convenient for scripting but exposes the password in
   shell history and the process list. The interactive prompt is preferred.
4. **Argon2id not bundled.** scrypt provides memory-hardness without extra
   dependencies; Argon2id would be a further option and drops cleanly into the
   `KeyDerivation` interface and KDF-parameter registry if `argon2-cffi` is added.
5. **Extraction TOCTOU.** There is a narrow window between the path-safety check
   and the file write. On a shared/hostile filesystem an attacker could try to
   swap a path component; single-user local use is not affected.
6. **Windows paths.** Path-safety logic targets POSIX. Windows is untested.

## Reporting

This is an educational project. If you find a vulnerability, please open an
issue describing the problem and a reproduction.
