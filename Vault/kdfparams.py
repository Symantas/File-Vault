"""Serialization and reconstruction of KDF parameters.

The :class:`~Vault.kdf.KdfParams` for a vault are stored next to the ciphertext
so the key can always be re-derived with the exact parameters used at encryption
time. This module owns the wire format and the algorithm registry, keeping that
concern out of both ``kdf.py`` (the algorithms) and ``cipher.py`` (the framing).

Wire format (big-endian, matches the rest of the project)::

    algo_id   (1 byte)
    key_size  (1 byte)
    salt_size (1 byte)
    tlv_count (1 byte)
    repeated tlv_count times:
        tag   (1 byte)
        value (8 bytes, unsigned)

The fixed 8-byte values and explicit ``tlv_count`` keep parsing trivial and
bounded, and let a future algorithm add parameters without a format change.
"""

import struct
from dataclasses import dataclass
from typing import Callable

from .errors import ContainerError
from .kdf import (
    ALGO_PBKDF2_SHA256,
    ALGO_SCRYPT,
    KdfParams,
    KeyDerivation,
    PBKDF2KeyDerivation,
    ScryptKeyDerivation,
)

_PREFIX = struct.Struct(">BBBB")  # algo_id, key_size, salt_size, tlv_count
_TLV = struct.Struct(">BQ")  # tag, value


def _build_pbkdf2(p: KdfParams) -> KeyDerivation:
    return PBKDF2KeyDerivation(
        iterations=p.extra["iterations"], key_size=p.key_size, salt_size=p.salt_size
    )


def _build_scrypt(p: KdfParams) -> KeyDerivation:
    return ScryptKeyDerivation(
        n=p.extra["n"], r=p.extra["r"], p=p.extra["p"],
        key_size=p.key_size, salt_size=p.salt_size,
    )


def _validate_pbkdf2(extra: dict[str, int]) -> None:
    if extra["iterations"] < 1:
        raise ContainerError("invalid PBKDF2 iteration count")


def _validate_scrypt(extra: dict[str, int]) -> None:
    n = extra["n"]
    if n < 2 or (n & (n - 1)) != 0:  # scrypt requires n to be a power of two > 1
        raise ContainerError("invalid scrypt parameter n")
    if extra["r"] < 1 or extra["p"] < 1:
        raise ContainerError("invalid scrypt parameter r or p")


@dataclass(frozen=True)
class _AlgorithmSpec:
    """Everything that varies between KDF algorithms, in one place."""

    algo_id: int
    name: str
    layout: tuple[tuple[int, str], ...]  # ordered (tag, param-name) entries
    builder: Callable[[KdfParams], KeyDerivation]
    validate_extra: Callable[[dict[str, int]], None]


# Single source of truth: adding a KDF means adding one entry here.
_SPECS: dict[int, _AlgorithmSpec] = {
    ALGO_PBKDF2_SHA256: _AlgorithmSpec(
        ALGO_PBKDF2_SHA256,
        "PBKDF2-HMAC-SHA256",
        ((0x01, "iterations"),),
        _build_pbkdf2,
        _validate_pbkdf2,
    ),
    ALGO_SCRYPT: _AlgorithmSpec(
        ALGO_SCRYPT,
        "scrypt",
        ((0x10, "n"), (0x11, "r"), (0x12, "p")),
        _build_scrypt,
        _validate_scrypt,
    ),
}


def _spec_for(algo_id: int) -> _AlgorithmSpec:
    """Look up an algorithm spec, raising the single canonical error if unknown."""
    try:
        return _SPECS[algo_id]
    except KeyError:
        raise ContainerError(f"unsupported KDF algorithm id: {algo_id}")


def algorithm_name(algo_id: int) -> str:
    """Return the human-readable name for a KDF algorithm id."""
    return _spec_for(algo_id).name


def serialize(params: KdfParams) -> bytes:
    """Serialize ``params`` to the KDF parameter block."""
    spec = _spec_for(params.algo_id)
    chunks = [_PREFIX.pack(params.algo_id, params.key_size, params.salt_size, len(spec.layout))]
    for tag, key in spec.layout:
        chunks.append(_TLV.pack(tag, params.extra[key]))
    return b"".join(chunks)


def deserialize(blob: bytes) -> tuple[KdfParams, int]:
    """Parse a KDF parameter block from the start of ``blob``.

    Returns ``(params, bytes_consumed)``. Raises :class:`ContainerError` on a
    malformed, truncated, or unknown block.
    """
    if len(blob) < _PREFIX.size:
        raise ContainerError("KDF parameter block is truncated")
    algo_id, key_size, salt_size, tlv_count = _PREFIX.unpack(blob[: _PREFIX.size])

    spec = _spec_for(algo_id)
    offset = _PREFIX.size
    extra: dict[str, int] = {}
    for _ in range(tlv_count):
        if offset + _TLV.size > len(blob):
            raise ContainerError("KDF parameter block is truncated")
        tag, value = _TLV.unpack(blob[offset : offset + _TLV.size])
        offset += _TLV.size
        key = next((k for t, k in spec.layout if t == tag), None)
        if key is None:
            raise ContainerError(f"unknown KDF parameter tag: {tag:#x}")
        extra[key] = value

    expected = {key for _, key in spec.layout}
    if extra.keys() != expected:
        raise ContainerError("KDF parameter block is missing required parameters")

    _validate_sizes(key_size, salt_size)
    spec.validate_extra(extra)
    return KdfParams(algo_id, key_size, salt_size, extra), offset


def _validate_sizes(key_size: int, salt_size: int) -> None:
    """Reject nonsensical sizes from an untrusted block.

    Crafted values (e.g. ``iterations=0`` or a non-power-of-two scrypt ``n``,
    handled per-algorithm by the spec validators) would otherwise reach the crypto
    backend *before* GCM authentication and surface as a ``ValueError`` — or even a
    Rust ``PanicException`` — instead of a clean :class:`ContainerError`.
    """
    if salt_size < 1:
        raise ContainerError("invalid KDF salt size")
    if key_size < 1:
        raise ContainerError("invalid KDF key size")


def kdf_from_params(params: KdfParams) -> KeyDerivation:
    """Rebuild a :class:`KeyDerivation` from stored parameters."""
    return _spec_for(params.algo_id).builder(params)
