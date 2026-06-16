"""Vault container (de)serialization for File-Vault.

A vault file wraps an encrypted payload with a small, versioned header so the
format can evolve without breaking older files::

    magic "FVLT" (4 bytes) | version (1 byte) | encrypted blob

The *plaintext* that gets encrypted carries the original file name so it can be
restored on extraction without leaking it on disk::

    name_len (2 bytes, big-endian) | name (utf-8) | file contents
"""

import struct

MAGIC = b"FVLT"
VERSION = 1

# Header is magic + a single version byte.
_HEADER = struct.Struct(">4sB")
# Payload prefix carrying the original file name length.
_NAME_LEN = struct.Struct(">H")
MAX_NAME_LEN = 0xFFFF


class PackError(Exception):
    """Raised when a vault container is malformed or unsupported."""


def pack_payload(name: str, data: bytes) -> bytes:
    """Combine an original ``name`` and file ``data`` into one plaintext blob."""
    encoded = name.encode("utf-8")
    if len(encoded) > MAX_NAME_LEN:
        raise PackError("file name is too long to store in a vault")
    return _NAME_LEN.pack(len(encoded)) + encoded + data


def unpack_payload(payload: bytes) -> tuple[str, bytes]:
    """Reverse :func:`pack_payload`, returning ``(name, data)``."""
    if len(payload) < _NAME_LEN.size:
        raise PackError("payload is too short to contain a file name")
    (name_len,) = _NAME_LEN.unpack(payload[:_NAME_LEN.size])
    start = _NAME_LEN.size
    end = start + name_len
    if len(payload) < end:
        raise PackError("payload is truncated: file name is incomplete")
    name = payload[start:end].decode("utf-8")
    return name, payload[end:]


def wrap(blob: bytes) -> bytes:
    """Add the vault header to an encrypted ``blob``."""
    return _HEADER.pack(MAGIC, VERSION) + blob


def unwrap(container: bytes) -> bytes:
    """Validate the header and return the inner encrypted blob.

    Raises:
        PackError: if the magic bytes or version are not recognized.
    """
    if len(container) < _HEADER.size:
        raise PackError("file is too short to be a vault container")
    magic, version = _HEADER.unpack(container[:_HEADER.size])
    if magic != MAGIC:
        raise PackError("not a File-Vault container (bad magic bytes)")
    if version != VERSION:
        raise PackError(f"unsupported vault version: {version}")
    return container[_HEADER.size:]
