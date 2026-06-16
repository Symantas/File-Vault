"""High-level vault orchestration.

:class:`VaultService` ties together the archiver, encryptor and container. It
depends only on the *abstractions* (:class:`~Vault.cipher.Encryptor`,
:class:`~Vault.archive.Archiver`) which are injected, so behaviour can be
reconfigured or tested without changing this class (Dependency Inversion).
"""

import os
from dataclasses import dataclass

from . import kdfparams
from .archive import Archiver, DirectoryArchiver
from .cipher import AesGcmEncryptor, Encryptor
from .container import Container, VaultContainer

VAULT_SUFFIX = ".vault"


@dataclass(frozen=True)
class VaultInfo:
    """Metadata about a vault, readable without the password."""

    version: int
    kdf_algorithm: str
    key_size: int
    salt_size: int
    parameters: dict[str, int]


class VaultService:
    """Encrypts and decrypts files *and* directories into vault containers."""

    def __init__(
        self,
        encryptor: Encryptor | None = None,
        archiver: Archiver | None = None,
        container: Container | None = None,
    ) -> None:
        self._encryptor = encryptor or AesGcmEncryptor()
        self._archiver = archiver or DirectoryArchiver()
        self._container = container or VaultContainer()

    def encrypt_path(
        self, source: str, password: str, destination: str | None = None
    ) -> str:
        """Encrypt the file or directory at ``source`` into one vault file.

        Returns the path of the written container (``<source>.vault`` by
        default). The container is created with owner-only permissions.
        """
        archive = self._archiver.pack(source)
        # Authenticate the container header so its version/magic cannot be altered.
        blob = self._encryptor.encrypt(
            archive, password, associated_data=self._container.header()
        )
        container = self._container.wrap(blob)

        if destination is None:
            destination = source.rstrip("/\\") + VAULT_SUFFIX

        self._write_private(destination, container)
        return destination

    def decrypt_path(
        self,
        source: str,
        password: str,
        destination_dir: str | None = None,
        overwrite: bool = False,
    ) -> list[str]:
        """Decrypt a vault ``source`` and restore its contents.

        Files are restored under ``destination_dir`` (the directory containing
        ``source`` by default), preserving the original names and tree layout.
        Returns the list of restored file paths.
        """
        archive = self._load_archive(source, password)

        if destination_dir is None:
            destination_dir = os.path.dirname(os.path.abspath(source))
        return self._archiver.unpack(archive, destination_dir, overwrite=overwrite)

    def rekey_path(
        self,
        source: str,
        old_password: str,
        new_password: str,
        new_encryptor: Encryptor | None = None,
        destination: str | None = None,
    ) -> str:
        """Re-encrypt a vault under a new password without extracting it to disk.

        Decrypts the payload with ``old_password`` and re-encrypts it with
        ``new_password``. Pass ``new_encryptor`` to also change the KDF (e.g. to
        upgrade PBKDF2 -> scrypt). Writes in place by default; if the old password
        is wrong the original file is left untouched (decryption fails first).
        """
        archive = self._load_archive(source, old_password)

        encryptor = new_encryptor or self._encryptor
        blob = encryptor.encrypt(
            archive, new_password, associated_data=self._container.header()
        )

        if destination is None:
            destination = source
        self._write_private(destination, self._container.wrap(blob))
        return destination

    def _load_archive(self, source: str, password: str) -> bytes:
        """Read a vault file and return its decrypted archive payload."""
        with open(source, "rb") as fh:
            container = fh.read()
        blob = self._container.unwrap(container)
        return self._encryptor.decrypt(
            blob, password, associated_data=self._container.header()
        )

    def inspect(self, source: str) -> VaultInfo:
        """Report a vault's format version and KDF parameters without decrypting.

        This metadata is stored in the clear (and authenticated), so no password
        is required. Raises :class:`~Vault.errors.ContainerError` if ``source``
        is not a valid vault.
        """
        with open(source, "rb") as fh:
            data = fh.read()

        blob = self._container.unwrap(data)
        params, _ = kdfparams.deserialize(blob)
        return VaultInfo(
            version=self._container.version,
            kdf_algorithm=kdfparams.algorithm_name(params.algo_id),
            key_size=params.key_size,
            salt_size=params.salt_size,
            parameters=dict(params.extra),
        )

    @staticmethod
    def _write_private(path: str, data: bytes) -> None:
        """Write ``data`` to ``path`` with 0600 permissions where supported.

        ``O_NOFOLLOW`` makes the open fail rather than follow a symlink planted
        at the output path, so we never truncate a symlink's target.
        """
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        flags |= getattr(os, "O_NOFOLLOW", 0)  # not available on some platforms
        fd = os.open(path, flags, 0o600)
        # os.fdopen takes ownership of fd and closes it on context exit.
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
