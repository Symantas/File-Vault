"""High-level vault orchestration.

:class:`VaultService` ties together the archiver, encryptor and container. It
depends only on the *abstractions* (:class:`~Vault.cipher.Encryptor`,
:class:`~Vault.archive.Archiver`) which are injected, so behaviour can be
reconfigured or tested without changing this class (Dependency Inversion).
"""

import os

from .archive import Archiver, DirectoryArchiver
from .cipher import AesGcmEncryptor, Encryptor
from .container import Container, VaultContainer

VAULT_SUFFIX = ".vault"


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
        with open(source, "rb") as fh:
            container = fh.read()

        blob = self._container.unwrap(container)
        archive = self._encryptor.decrypt(
            blob, password, associated_data=self._container.header()
        )

        if destination_dir is None:
            destination_dir = os.path.dirname(os.path.abspath(source))
        return self._archiver.unpack(archive, destination_dir, overwrite=overwrite)

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
