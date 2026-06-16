"""Archiving of files and directories into a single byte stream.

An :class:`Archiver` flattens a path — a single file *or* a whole directory tree
— into one ``bytes`` object that can then be encrypted, and restores it on the
way back out.

The built-in :class:`DirectoryArchiver` uses a small custom format that we fully
control, which lets extraction defend against the classic archive attacks
(path traversal / "Zip Slip", CWE-22) by construction. Symbolic links are not
followed when reading and are never recreated when writing.

Archive layout::

    entry_count (4 bytes, big-endian)
    repeated entry_count times:
        flags    (1 byte)   bit 0 set => directory
        path_len (2 bytes)  length of the relative path
        path     (utf-8, forward-slash separated, relative)
        size     (8 bytes)  file size            (files only)
        content  (size bytes)                     (files only)
"""

import os
import struct
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass

from .errors import ArchiveError, OverwriteError, PathTraversalError

_COUNT = struct.Struct(">I")
_FLAGS = struct.Struct(">B")
_PATH_LEN = struct.Struct(">H")
_SIZE = struct.Struct(">Q")
_FLAG_DIR = 0b1
MAX_PATH_LEN = 0xFFFF


@dataclass(frozen=True)
class _Entry:
    path: str  # relative, forward-slash separated
    is_dir: bool
    content: bytes = b""


class Archiver(ABC):
    """Packs a filesystem path into bytes and unpacks it again."""

    @abstractmethod
    def pack(self, source: str) -> bytes:
        """Serialize the file or directory at ``source`` into bytes."""

    @abstractmethod
    def unpack(self, data: bytes, destination_dir: str, overwrite: bool = False) -> list[str]:
        """Restore an archive under ``destination_dir``; return written file paths.

        Contract (all implementations must honor it):

        - If ``overwrite`` is ``False`` (default), an existing target file MUST
          raise :class:`~Vault.errors.OverwriteError` and MUST NOT be modified.
          Existing directories may be reused.
        - If ``overwrite`` is ``True``, existing files are replaced.
        - Every entry path MUST stay within ``destination_dir``; an entry that
          escapes it MUST raise :class:`~Vault.errors.PathTraversalError`.
        """


class DirectoryArchiver(Archiver):
    """Recursively archives files and directories using a safe custom format."""

    def pack(self, source: str) -> bytes:
        source = os.path.abspath(source)
        if not os.path.exists(source):
            raise ArchiveError(f"source does not exist: {source}")
        if os.path.islink(source):
            raise ArchiveError("refusing to archive a symbolic link")

        base = os.path.dirname(source)
        entries = self._collect(source, base)
        return self._serialize(entries)

    def unpack(self, data: bytes, destination_dir: str, overwrite: bool = False) -> list[str]:
        destination_dir = os.path.abspath(destination_dir)
        os.makedirs(destination_dir, exist_ok=True)
        root = os.path.realpath(destination_dir)

        written: list[str] = []
        for entry in self._deserialize(data):
            target = self._safe_target(root, entry.path)
            if entry.is_dir:
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            if os.path.exists(target) and not overwrite:
                raise OverwriteError(f"refusing to overwrite existing file: {target}")
            # 'wb' truncates a regular file; O_NOFOLLOW would be stronger but is
            # not portable. We never create symlinks, so the tree we write is
            # link-free as long as the destination is.
            with open(target, "wb") as fh:
                fh.write(entry.content)
            written.append(target)
        return written

    # -- packing helpers ---------------------------------------------------

    def _collect(self, source: str, base: str) -> list[_Entry]:
        rel = self._relpath(source, base)
        if os.path.isfile(source):
            with open(source, "rb") as fh:
                return [_Entry(rel, is_dir=False, content=fh.read())]

        entries: list[_Entry] = [_Entry(rel, is_dir=True)]
        # followlinks=False prevents symlink loops and reading outside the tree.
        for dirpath, dirnames, filenames in os.walk(source, followlinks=False):
            # Sorted, non-symlinked subdirs: used both for entries and for descent.
            subdirs = [
                d for d in sorted(dirnames)
                if not os.path.islink(os.path.join(dirpath, d))
            ]
            for name in subdirs:
                full = os.path.join(dirpath, name)
                entries.append(_Entry(self._relpath(full, base), is_dir=True))
            for name in sorted(filenames):
                full = os.path.join(dirpath, name)
                if os.path.islink(full):
                    continue  # skip symlinked files
                with open(full, "rb") as fh:
                    entries.append(_Entry(self._relpath(full, base), is_dir=False, content=fh.read()))
            dirnames[:] = subdirs  # descend only into the non-symlinked subdirs
        return entries

    @staticmethod
    def _relpath(path: str, base: str) -> str:
        rel = os.path.relpath(path, base)
        return rel.replace(os.sep, "/")

    def _serialize(self, entries: list[_Entry]) -> bytes:
        chunks = [_COUNT.pack(len(entries))]
        for entry in entries:
            encoded = entry.path.encode("utf-8")
            if len(encoded) > MAX_PATH_LEN:
                raise ArchiveError(f"path too long to archive: {entry.path}")
            flags = _FLAG_DIR if entry.is_dir else 0
            chunks.append(_FLAGS.pack(flags))
            chunks.append(_PATH_LEN.pack(len(encoded)))
            chunks.append(encoded)
            if not entry.is_dir:
                chunks.append(_SIZE.pack(len(entry.content)))
                chunks.append(entry.content)
        return b"".join(chunks)

    # -- unpacking helpers -------------------------------------------------

    def _deserialize(self, data: bytes) -> Iterator[_Entry]:
        view = memoryview(data)
        offset = 0

        def take(n: int) -> bytes:
            nonlocal offset
            if offset + n > len(view):
                raise ArchiveError("archive is truncated")
            chunk = view[offset : offset + n]
            offset += n
            return bytes(chunk)

        (count,) = _COUNT.unpack(take(_COUNT.size))
        for _ in range(count):
            (flags,) = _FLAGS.unpack(take(_FLAGS.size))
            (path_len,) = _PATH_LEN.unpack(take(_PATH_LEN.size))
            path = take(path_len).decode("utf-8")
            is_dir = bool(flags & _FLAG_DIR)
            if is_dir:
                yield _Entry(path, is_dir=True)
            else:
                (size,) = _SIZE.unpack(take(_SIZE.size))
                yield _Entry(path, is_dir=False, content=take(size))

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
