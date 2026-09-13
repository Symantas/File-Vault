"""Versioned vault container framing.

A :class:`Container` adds a small header to an encrypted blob so the format is
self-identifying and can evolve over time::

    magic "FVLT" (4 bytes) | version (1 byte) | encrypted blob

Keeping this behind an abstraction lets :class:`~Vault.service.VaultService`
depend on the interface rather than a concrete format (Dependency Inversion), and
lets a new format be added as a new subclass (Open/Closed).
"""

import struct
from abc import ABC, abstractmethod

from .errors import ContainerError


class Container(ABC):
    """Frames an encrypted blob with a self-identifying header."""

    @property
    @abstractmethod
    def version(self) -> int:
        """The format version this container reads and writes."""

    @abstractmethod
    def header(self) -> bytes:
        """Return the exact header bytes (used as authenticated associated data)."""

    @abstractmethod
    def wrap(self, blob: bytes) -> bytes:
        """Prepend the container header to ``blob``."""

    @abstractmethod
    def unwrap(self, container: bytes) -> bytes:
        """Validate the header and return the inner encrypted blob."""


class VaultContainer(Container):
    """The current File-Vault container: a magic + version header."""

    MAGIC = b"FVLT"
    VERSION = 4  # v4: DEK + key slots, streamed chunked payload

    _HEADER = struct.Struct(">4sB")

    @property
    def version(self) -> int:
        return self.VERSION

    def header(self) -> bytes:
        return self._HEADER.pack(self.MAGIC, self.VERSION)

    def wrap(self, blob: bytes) -> bytes:
        return self.header() + blob

    def unwrap(self, container: bytes) -> bytes:
        if len(container) < self._HEADER.size:
            raise ContainerError("file is too short to be a vault container")
        magic, version = self._HEADER.unpack(container[: self._HEADER.size])
        if magic != self.MAGIC:
            raise ContainerError("not a File-Vault container (bad magic bytes)")
        if version != self.VERSION:
            raise ContainerError(f"unsupported vault version: {version}")
        return container[self._HEADER.size :]
