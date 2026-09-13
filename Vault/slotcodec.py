"""Wire framing for the key-slot section of a vault.

Each slot is ``slot_type (1) | body_len (2) | body``. This module owns only the
framing; the per-type body format and crypto live in :mod:`Vault.slots`.
"""

import struct

from .errors import ContainerError

_SLOT_HEADER = struct.Struct(">BH")  # slot_type, body_len
_SLOT_COUNT = struct.Struct(">B")
MAX_BODY_LEN = 0xFFFF


def serialize_slot(slot_type: int, body: bytes) -> bytes:
    """Frame one slot body with its type and length."""
    if len(body) > MAX_BODY_LEN:
        raise ContainerError("key-slot body too large")
    return _SLOT_HEADER.pack(slot_type, len(body)) + body


def serialize_section(slots: list[tuple[int, bytes]]) -> bytes:
    """Serialize the whole slot section: count followed by framed slots."""
    if not 1 <= len(slots) <= 0xFF:
        raise ContainerError("a vault must have between 1 and 255 key slots")
    out = [_SLOT_COUNT.pack(len(slots))]
    out += [serialize_slot(t, b) for t, b in slots]
    return b"".join(out)


def read_section(fh) -> list[tuple[int, bytes]]:
    """Read the slot section from a binary file object, returning ``(type, body)``s."""
    (count,) = _SLOT_COUNT.unpack(_read_exact(fh, _SLOT_COUNT.size))
    if count == 0:
        raise ContainerError("vault has no key slots")
    slots: list[tuple[int, bytes]] = []
    for _ in range(count):
        slot_type, body_len = _SLOT_HEADER.unpack(_read_exact(fh, _SLOT_HEADER.size))
        slots.append((slot_type, _read_exact(fh, body_len)))
    return slots


def _read_exact(fh, n: int) -> bytes:
    data = fh.read(n)
    if len(data) < n:
        raise ContainerError("vault is truncated (key-slot section)")
    return data


def parse_section(blob: bytes, offset: int = 0) -> tuple[list[tuple[int, bytes]], int]:
    """Parse the slot section, returning ``(slots, bytes_consumed_end_offset)``.

    ``slots`` is a list of ``(slot_type, body)``. Raises :class:`ContainerError`
    on a malformed or truncated section.
    """
    if len(blob) < offset + _SLOT_COUNT.size:
        raise ContainerError("vault is truncated (missing slot count)")
    (count,) = _SLOT_COUNT.unpack(blob[offset : offset + _SLOT_COUNT.size])
    if count == 0:
        raise ContainerError("vault has no key slots")
    offset += _SLOT_COUNT.size

    slots: list[tuple[int, bytes]] = []
    for _ in range(count):
        if len(blob) < offset + _SLOT_HEADER.size:
            raise ContainerError("vault is truncated (slot header)")
        slot_type, body_len = _SLOT_HEADER.unpack(blob[offset : offset + _SLOT_HEADER.size])
        offset += _SLOT_HEADER.size
        if len(blob) < offset + body_len:
            raise ContainerError("vault is truncated (slot body)")
        slots.append((slot_type, blob[offset : offset + body_len]))
        offset += body_len
    return slots, offset
