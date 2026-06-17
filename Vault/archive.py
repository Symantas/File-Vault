"""Streaming archiving of files and directories.

An :class:`Archiver` flattens a path — a single file *or* a whole directory tree
— into a *stream* of bytes that can be encrypted chunk-by-chunk, and restores it
from such a stream, so multi-gigabyte inputs never need to fit in memory.

The built-in :class:`DirectoryArchiver` uses a small self-delimited format we
fully control, which lets extraction defend against the classic archive attacks
(path traversal / "Zip Slip", CWE-22) by construction. Symbolic links are not
followed when reading and are never recreated when writing.

Stream framing (big-endian), terminated by an END record::

    repeated:
        record_type (1)   0x00 = dir, 0x01 = file, 0xFF = END
        if dir or file:
            path_len (2) | path (utf-8, forward-slash separated, relative)
        if file:
            repeated: data_len (4) | data        # data_len > 0
            data_len == 0                          # end of this file's content
    END
"""

import os
import struct
from abc import ABC, abstractmethod
from collections.abc import Iterator

from .errors import ArchiveError, OverwriteError, PathTraversalError

_U16 = struct.Struct(">H")
_U32 = struct.Struct(">I")
RECORD_DIR = 0x00
RECORD_FILE = 0x01
RECORD_END = 0xFF
MAX_PATH_LEN = 0xFFFF
CONTENT_CHUNK = 64 * 1024
MAX_CONTENT_CHUNK = 1 << 26  # 64 MiB cap on a single declared data run


class Archiver(ABC):
    """Packs a filesystem path into a byte stream and unpacks it again."""

    @abstractmethod
    def pack_stream(self, source: str) -> Iterator[bytes]:
        """Yield the archive of ``source`` as a stream of byte chunks."""

    @abstractmethod
    def unpack_stream(
        self, chunks: Iterator[bytes], destination_dir: str, overwrite: bool = False
    ) -> list[str]:
        """Restore an archive stream under ``destination_dir``; return written paths.

        Contract (all implementations must honor it):

        - If ``overwrite`` is ``False`` (default), an existing target file MUST
          raise :class:`~Vault.errors.OverwriteError` and MUST NOT be modified.
          Existing directories may be reused.
        - If ``overwrite`` is ``True``, existing files are replaced.
        - Every entry path MUST stay within ``destination_dir``; an entry that
          escapes it MUST raise :class:`~Vault.errors.PathTraversalError`.
        """

    # Convenience wrappers for callers that have the whole archive in memory.
    def pack(self, source: str) -> bytes:
        return b"".join(self.pack_stream(source))

    def unpack(self, data: bytes, destination_dir: str, overwrite: bool = False) -> list[str]:
        return self.unpack_stream(iter((data,)), destination_dir, overwrite)


class DirectoryArchiver(Archiver):
    """Recursively archives files and directories using a safe streaming format."""

    def pack_stream(self, source: str) -> Iterator[bytes]:
        source = os.path.abspath(source)
        if not os.path.exists(source):
            raise ArchiveError(f"source does not exist: {source}")
        if os.path.islink(source):
            raise ArchiveError("refusing to archive a symbolic link")

        base = os.path.dirname(source)
        if os.path.isfile(source):
            yield from self._file_records(source, base)
        else:
            yield _dir_record(self._relpath(source, base))
            # followlinks=False prevents symlink loops and reading outside the tree.
            for dirpath, dirnames, filenames in os.walk(source, followlinks=False):
                subdirs = [
                    d for d in sorted(dirnames)
                    if not os.path.islink(os.path.join(dirpath, d))
                ]
                for name in subdirs:
                    yield _dir_record(self._relpath(os.path.join(dirpath, name), base))
                for name in sorted(filenames):
                    full = os.path.join(dirpath, name)
                    if os.path.islink(full):
                        continue  # skip symlinked files
                    yield from self._file_records(full, base)
                dirnames[:] = subdirs  # descend only into non-symlinked subdirs
        yield bytes([RECORD_END])

    def unpack_stream(
        self, chunks: Iterator[bytes], destination_dir: str, overwrite: bool = False
    ) -> list[str]:
        destination_dir = os.path.abspath(destination_dir)
        os.makedirs(destination_dir, exist_ok=True)
        root = os.path.realpath(destination_dir)

        reader = _StreamReader(chunks)
        written: list[str] = []
        while True:
            marker = reader.read(1)
            if not marker:
                raise ArchiveError("archive stream is truncated (missing END marker)")
            record_type = marker[0]
            if record_type == RECORD_END:
                break
            if record_type == RECORD_DIR:
                target = self._safe_target(root, _read_path(reader))
                os.makedirs(target, exist_ok=True)
            elif record_type == RECORD_FILE:
                target = self._safe_target(root, _read_path(reader))
                os.makedirs(os.path.dirname(target), exist_ok=True)
                if os.path.exists(target) and not overwrite:
                    raise OverwriteError(f"refusing to overwrite existing file: {target}")
                self._write_file(target, reader)
                written.append(target)
            else:
                raise ArchiveError(f"unknown archive record type: {record_type}")
        return written

    # -- packing helpers ---------------------------------------------------

    def _file_records(self, full: str, base: str) -> Iterator[bytes]:
        yield _file_header(self._relpath(full, base))
        with open(full, "rb") as fh:
            while True:
                data = fh.read(CONTENT_CHUNK)
                if not data:
                    break
                yield _U32.pack(len(data)) + data
        yield _U32.pack(0)  # end of this file's content

    @staticmethod
    def _relpath(path: str, base: str) -> str:
        return os.path.relpath(path, base).replace(os.sep, "/")

    # -- unpacking helpers -------------------------------------------------

    @staticmethod
    def _write_file(target: str, reader: "_StreamReader") -> None:
        # O_NOFOLLOW refuses to follow a symlink planted at the target path.
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(target, flags, 0o600)
        with os.fdopen(fd, "wb") as fh:
            while True:
                (data_len,) = _U32.unpack(reader.read_exact(_U32.size))
                if data_len == 0:
                    break
                if data_len > MAX_CONTENT_CHUNK:
                    raise ArchiveError("archive declares an oversized data run")
                fh.write(reader.read_exact(data_len))

    @staticmethod
    def _safe_target(root: str, rel_path: str) -> str:
        """Resolve ``rel_path`` under ``root``, rejecting any escape attempt."""
        if not rel_path or rel_path.startswith("/") or "\\" in rel_path:
            raise PathTraversalError(f"unsafe archive path: {rel_path!r}")
        parts = rel_path.split("/")
        if any(part in ("", ".", "..") for part in parts):
            raise PathTraversalError(f"unsafe archive path: {rel_path!r}")

        target = os.path.join(root, *parts)
        # Defense in depth: ensure the resolved path stays within root even if a
        # parent directory is (or becomes) a symlink.
        resolved = os.path.realpath(target)
        if resolved != root and not resolved.startswith(root + os.sep):
            raise PathTraversalError(f"archive path escapes destination: {rel_path!r}")
        return target


def _dir_record(rel_path: str) -> bytes:
    return bytes([RECORD_DIR]) + _encode_path(rel_path)


def _file_header(rel_path: str) -> bytes:
    return bytes([RECORD_FILE]) + _encode_path(rel_path)


def _encode_path(rel_path: str) -> bytes:
    encoded = rel_path.encode("utf-8")
    if len(encoded) > MAX_PATH_LEN:
        raise ArchiveError(f"path too long to archive: {rel_path}")
    return _U16.pack(len(encoded)) + encoded


def _read_path(reader: "_StreamReader") -> str:
    (path_len,) = _U16.unpack(reader.read_exact(_U16.size))
    return reader.read_exact(path_len).decode("utf-8")


class _StreamReader:
    """Pull exact byte counts from an iterator of byte chunks."""

    def __init__(self, chunks: Iterator[bytes]) -> None:
        self._it = iter(chunks)
        self._buf = b""
        self._eof = False

    def _fill(self, n: int) -> None:
        while len(self._buf) < n and not self._eof:
            try:
                self._buf += next(self._it)
            except StopIteration:
                self._eof = True

    def read(self, n: int) -> bytes:
        """Return up to ``n`` bytes (fewer only at end of stream)."""
        self._fill(n)
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def read_exact(self, n: int) -> bytes:
        out = self.read(n)
        if len(out) < n:
            raise ArchiveError("archive stream is truncated")
        return out
