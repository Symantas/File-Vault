# Security Notes

This document describes File-Vault's threat model, the hardening measures in
place, and known limitations. It reflects the state of the code as of the
current revision.

## Cryptographic design

| Concern              | Choice                                                       |
| -------------------- | ----------------------------------------------------------- |
| Confidentiality      | AES-256-GCM                                                  |
| Integrity / tamper   | GCM authentication tag (AEAD) — decryption fails on changes |
| Key derivation       | PBKDF2-HMAC-SHA256, 480,000 iterations (OWASP 2023 minimum)  |
| Salt                 | 16 random bytes per encryption (`os.urandom`)               |
| Nonce                | 12 random bytes per encryption (`os.urandom`)               |

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
- **Plaintext file names on disk.** Names and the directory layout are stored
  *inside* the encrypted payload, never in the clear.

## Known limitations

These are documented trade-offs, not silent gaps:

1. **In-memory processing.** Files/folders are read fully into memory before
   encryption and after decryption. Extremely large inputs can exhaust RAM.
   Streaming/chunked encryption is future work.
2. **Password material in memory.** Python strings cannot be reliably zeroed,
   so the password may linger in memory until garbage collected.
3. **`--password` flag.** Convenient for scripting but exposes the password in
   shell history and the process list. The interactive prompt is preferred.
4. **PBKDF2 vs. memory-hard KDFs.** PBKDF2 is solid but not memory-hard.
   Argon2id would resist GPU/ASIC cracking better; the `KeyDerivation`
   interface makes this a drop-in future addition.
5. **Unauthenticated header.** The 5-byte magic/version header is outside the
   AEAD. There is no practical exploit (any change to the encrypted blob fails
   authentication, and an unknown version is rejected), but the header is not
   cryptographically bound to the ciphertext.
6. **Extraction TOCTOU.** There is a narrow window between the path-safety check
   and the file write. On a shared/hostile filesystem an attacker could try to
   swap a path component; single-user local use is not affected.
7. **Windows paths.** Path-safety logic targets POSIX. Windows is untested.

## Reporting

This is an educational project. If you find a vulnerability, please open an
issue describing the problem and a reproduction.
