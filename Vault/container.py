"""Versioned vault container framing.

A :class:`VaultContainer` adds a small header to an encrypted blob so the format
is self-identifying and can evolve over time::

    magic "FVLT" (4 bytes) | version (1 byte) | encrypted blob
"""

import struct

from .errors import ContainerError


class VaultContainer:
    """Wraps and unwraps encrypted blobs with a magic + version header."""

    MAGIC = b"FVLT"
    VERSION = 2  # v2: payload is always an archive (supports files and folders)

    _HEADER = struct.Struct(">4sB")

    def wrap(self, blob: bytes) -> bytes:
        """Prepend the container header to ``blob``."""
        return self._HEADER.pack(self.MAGIC, self.VERSION) + blob

    def unwrap(self, container: bytes) -> bytes:
        """Validate the header and return the inner encrypted blob."""
        if len(container) < self._HEADER.size:
            raise ContainerError("file is too short to be a vault container")
        magic, version = self._HEADER.unpack(container[: self._HEADER.size])
        if magic != self.MAGIC:
            raise ContainerError("not a File-Vault container (bad magic bytes)")
        if version != self.VERSION:
            raise ContainerError(f"unsupported vault version: {version}")
        return container[self._HEADER.size :]
