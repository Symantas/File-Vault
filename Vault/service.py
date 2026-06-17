"""High-level vault orchestration (v4: DEK + key slots + streamed payload).

:class:`VaultService` ties together the archiver, container, key slots and the
chunked stream cipher. A random Data Encryption Key (DEK) encrypts the payload
once; each key slot stores that DEK wrapped under a different secret, so a vault
can be unlocked by any of several passwords (and, later, recipients) and slots
can be added/removed without re-encrypting the payload.
"""

import os
import shutil
import struct
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass

from . import kdfparams, slotcodec
from .archive import Archiver, DirectoryArchiver
from .container import Container, VaultContainer
from .errors import ContainerError, DecryptionError, OverwriteError, SlotError
from .kdf import KeyDerivation, PBKDF2KeyDerivation
from .slots import (
    DEK_SIZE,
    SLOT_PASSWORD,
    PasswordSlot,
    slot_name,
    unlock_slot,
)
from .stream import CHUNK_PLAINTEXT, ChunkStreamEncryptor

VAULT_SUFFIX = ".vault"
_CHUNK_SIZE = struct.Struct(">I")
_MAX_CHUNK_SIZE = CHUNK_PLAINTEXT * 1024
_READ_BLOCK = CHUNK_PLAINTEXT


@dataclass(frozen=True)
class SlotInfo:
    """Description of one key slot, readable without unlocking the vault."""

    index: int
    type: str
    kdf_algorithm: str | None = None
    parameters: dict[str, int] | None = None


@dataclass(frozen=True)
class VaultInfo:
    """Metadata about a vault, readable without the password."""

    version: int
    slots: list[SlotInfo]


class VaultService:
    """Encrypts and decrypts files and directories as multi-key vault containers."""

    def __init__(
        self,
        archiver: Archiver | None = None,
        container: Container | None = None,
        default_kdf: KeyDerivation | None = None,
    ) -> None:
        self._archiver = archiver or DirectoryArchiver()
        self._container = container or VaultContainer()
        self._default_kdf = default_kdf or PBKDF2KeyDerivation()

    # -- public API --------------------------------------------------------

    def encrypt_path(
        self,
        source: str,
        *,
        passwords: tuple[str, ...] = (),
        recipients: tuple = (),
        destination: str | None = None,
        chunk_size: int = CHUNK_PLAINTEXT,
    ) -> str:
        """Encrypt a file or directory into a vault unlocked by any given secret.

        At least one password (or, later, recipient) is required. Returns the
        path of the written container (``<source>.vault`` by default).
        """
        if not passwords and not recipients:
            raise ValueError("at least one password or recipient is required")

        dek = os.urandom(DEK_SIZE)
        slots = self._build_slots(dek, passwords, recipients)

        if destination is None:
            destination = source.rstrip("/\\") + VAULT_SUFFIX

        with self._create_private(destination) as fh:
            fh.write(self._container.header())
            fh.write(slotcodec.serialize_section(slots))
            fh.write(_CHUNK_SIZE.pack(chunk_size))
            encryptor = ChunkStreamEncryptor(dek, chunk_size)
            base_aad = self._base_aad(chunk_size)
            for chunk in encryptor.encrypt_stream(self._archiver.pack_stream(source), base_aad):
                fh.write(chunk)
        return destination

    def decrypt_path(
        self,
        source: str,
        *,
        password: str | None = None,
        identity: object | None = None,
        destination_dir: str | None = None,
        overwrite: bool = False,
    ) -> list[str]:
        """Decrypt a vault and restore its contents, returning written paths.

        The payload is verified chunk-by-chunk while extracting into a temporary
        staging directory; nothing appears in ``destination_dir`` unless the whole
        stream authenticates, so a truncated/tampered vault leaves no partial output.
        """
        with open(source, "rb") as fh:
            self._read_header(fh)
            slots = slotcodec.read_section(fh)
            dek = self._recover_dek(slots, password=password, identity=identity)
            chunk_size = self._read_chunk_size(fh)

            if destination_dir is None:
                destination_dir = os.path.dirname(os.path.abspath(source))
            os.makedirs(destination_dir, exist_ok=True)

            encryptor = ChunkStreamEncryptor(dek, chunk_size)
            plaintext = encryptor.decrypt_stream(_iter_file(fh), self._base_aad(chunk_size))
            return self._extract_staged(plaintext, destination_dir, overwrite)

    def rekey_path(
        self,
        source: str,
        old_password: str,
        new_password: str,
        *,
        destination: str | None = None,
    ) -> str:
        """Change a vault's password by rewrapping the DEK; payload is copied as-is."""
        with open(source, "rb") as fh:
            header = self._read_header(fh)
            slots = slotcodec.read_section(fh)
            dek = self._recover_dek(slots, password=old_password)
            chunk_size_bytes = _read_exact(fh, _CHUNK_SIZE.size)

            new_slots = self._build_slots(dek, (new_password,), ())
            if destination is None:
                destination = source

            tmp = destination + ".rekey.tmp"
            try:
                with self._create_private(tmp) as out:
                    out.write(header)
                    out.write(slotcodec.serialize_section(new_slots))
                    out.write(chunk_size_bytes)
                    shutil.copyfileobj(fh, out)  # payload passthrough (no re-encrypt)
                os.replace(tmp, destination)
            except BaseException:
                _silent_remove(tmp)
                raise
        return destination

    def inspect(self, source: str) -> VaultInfo:
        """Report a vault's version and key slots without unlocking it."""
        with open(source, "rb") as fh:
            self._read_header(fh)
            slots = slotcodec.read_section(fh)
        return VaultInfo(
            version=self._container.version,
            slots=[self._describe_slot(i, t, b) for i, (t, b) in enumerate(slots)],
        )

    # -- slot helpers ------------------------------------------------------

    def _build_slots(self, dek, passwords, recipients) -> list[tuple[int, bytes]]:
        slots: list[tuple[int, bytes]] = []
        for password in passwords:
            slot = PasswordSlot(self._default_kdf, password)
            slots.append((SLOT_PASSWORD, slot.wrap(dek, self._slot_aad(SLOT_PASSWORD))))
        for recipient in recipients:
            slots.append(self._build_recipient_slot(dek, recipient))
        return slots

    def _build_recipient_slot(self, dek, recipient) -> tuple[int, bytes]:
        raise NotImplementedError("recipient slots arrive in a later phase")

    def _recover_dek(self, slots, *, password=None, identity=None) -> bytes:
        for slot_type, body in slots:
            dek = unlock_slot(
                slot_type, body, self._slot_aad(slot_type),
                password=password, identity=identity,
            )
            if dek is not None:
                return dek
        raise DecryptionError("no key slot could be unlocked with the given secret")

    def _describe_slot(self, index: int, slot_type: int, body: bytes) -> SlotInfo:
        name = slot_name(slot_type)
        if slot_type == SLOT_PASSWORD:
            params, _ = kdfparams.deserialize(body)
            return SlotInfo(index, name, kdfparams.algorithm_name(params.algo_id), dict(params.extra))
        return SlotInfo(index, name)

    # -- AAD ---------------------------------------------------------------

    def _slot_aad(self, slot_type: int) -> bytes:
        return self._container.header() + bytes([slot_type])

    def _base_aad(self, chunk_size: int) -> bytes:
        return self._container.header() + _CHUNK_SIZE.pack(chunk_size)

    # -- container reading -------------------------------------------------

    def _read_header(self, fh) -> bytes:
        header = _read_exact(fh, len(self._container.header()))
        self._container.unwrap(header)  # validates magic + version, raises ContainerError
        return header

    def _read_chunk_size(self, fh) -> int:
        (chunk_size,) = _CHUNK_SIZE.unpack(_read_exact(fh, _CHUNK_SIZE.size))
        if not 1 <= chunk_size <= _MAX_CHUNK_SIZE:
            raise ContainerError("vault declares an invalid chunk size")
        return chunk_size

    # -- staged extraction -------------------------------------------------

    def _extract_staged(self, plaintext, destination_dir, overwrite) -> list[str]:
        staging = tempfile.mkdtemp(prefix=".fv-", dir=destination_dir)
        try:
            self._archiver.unpack_stream(plaintext, staging, overwrite=True)
            return _merge_tree(staging, destination_dir, overwrite)
        finally:
            shutil.rmtree(staging, ignore_errors=True)

    # -- private file creation --------------------------------------------

    @staticmethod
    def _create_private(path: str):
        """Open ``path`` for writing with 0600 perms, refusing to follow a symlink."""
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        return os.fdopen(os.open(path, flags, 0o600), "wb")


# -- module helpers --------------------------------------------------------

def _read_exact(fh, n: int) -> bytes:
    data = fh.read(n)
    if len(data) < n:
        raise ContainerError("vault is truncated")
    return data


def _iter_file(fh, block: int = _READ_BLOCK) -> Iterator[bytes]:
    while True:
        data = fh.read(block)
        if not data:
            return
        yield data


def _merge_tree(staging: str, destination_dir: str, overwrite: bool) -> list[str]:
    """Move a fully-extracted staging tree into the destination, atomically per file.

    All overwrite conflicts are detected *before* any file is moved, so a refused
    overwrite leaves the destination untouched.
    """
    files: list[tuple[str, str]] = []  # (staged_path, dest_path)
    dirs: list[str] = []
    for dirpath, dirnames, filenames in os.walk(staging):
        rel_dir = os.path.relpath(dirpath, staging)
        for name in dirnames:
            dirs.append(os.path.normpath(os.path.join(destination_dir, rel_dir, name)))
        for name in filenames:
            staged = os.path.join(dirpath, name)
            dest = os.path.normpath(os.path.join(destination_dir, rel_dir, name))
            files.append((staged, dest))

    if not overwrite:
        existing = [dest for _, dest in files if os.path.exists(dest)]
        if existing:
            raise OverwriteError(f"refusing to overwrite existing file: {existing[0]}")

    for d in dirs:
        os.makedirs(d, exist_ok=True)
    written: list[str] = []
    for staged, dest in files:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        os.replace(staged, dest)
        written.append(dest)
    return written


def _silent_remove(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass
