"""Offline brute-force proof of concept.

This demonstrates the *real* residual threat against any password-based vault: an
attacker who obtains a ``.vault`` file can guess passwords entirely offline,
because the file is self-contained (salt, nonce, KDF parameters, ciphertext+tag).
A correct guess is recognized when GCM authentication succeeds.

The only defense is the KDF work factor — which is exactly why File-Vault now
stores the KDF parameters in the vault, so the factor can be raised over time.
These tests prove the attack works against a weak password and assert (without
timing flakiness) that the *stored* parameters drive key derivation.
"""

import pytest

from Vault import kdfparams
from Vault.cipher import AesGcmEncryptor
from Vault.errors import DecryptionError
from Vault.kdf import PBKDF2KeyDerivation

# A tiny "leaked password" dictionary an attacker might try.
WORDLIST = ["123456", "password", "letmein", "hunter2", "correcthorse", "qwerty"]


def _crack(blob: bytes, wordlist: list[str]) -> str | None:
    """Attacker's offline loop: trial-decrypt each candidate password."""
    attacker = AesGcmEncryptor(PBKDF2KeyDerivation())  # attacker's own config is ignored
    for candidate in wordlist:
        try:
            attacker.decrypt(blob, candidate)
            return candidate  # GCM tag verified -> correct password
        except DecryptionError:
            continue
    return None


def test_weak_password_is_recovered_offline():
    # Victim encrypts a secret with a weak password and a low work factor.
    victim = AesGcmEncryptor(PBKDF2KeyDerivation(iterations=1000))
    blob = victim.encrypt(b"bank PIN: 4242", "hunter2")

    # The attacker, with only the blob, recovers the password from a wordlist.
    assert _crack(blob, WORDLIST) == "hunter2"


def test_password_not_in_wordlist_survives():
    victim = AesGcmEncryptor(PBKDF2KeyDerivation(iterations=1000))
    blob = victim.encrypt(b"secret", "a-strong-unguessed-passphrase")
    assert _crack(blob, WORDLIST) is None


def test_stored_parameters_drive_derivation():
    # Mitigation check (deterministic, not timing-based): the work factor actually
    # used on decrypt is the one stored in the vault, regardless of the decrypting
    # encryptor's own configuration. Raising the default therefore never breaks an
    # existing vault, and a higher stored factor genuinely slows each guess.
    high = 250_000
    victim = AesGcmEncryptor(PBKDF2KeyDerivation(iterations=high))
    blob = victim.encrypt(b"secret", "pw")

    params, _ = kdfparams.deserialize(blob)
    assert params.extra["iterations"] == high

    # A decryptor configured with a *different* (low) factor still succeeds,
    # proving it derives the key from the stored params, not its own.
    other = AesGcmEncryptor(PBKDF2KeyDerivation(iterations=1))
    assert other.decrypt(blob, "pw") == b"secret"
