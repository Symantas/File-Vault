import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Vault import packer  # noqa: E402
from Vault.packer import PackError  # noqa: E402


def test_payload_round_trip():
    name, data = "report.pdf", b"\x00\x01\x02binary"
    name2, data2 = packer.unpack_payload(packer.pack_payload(name, data))
    assert (name2, data2) == (name, data)


def test_payload_unicode_name():
    name, data = "résumé—é.txt", b"x"
    out_name, out_data = packer.unpack_payload(packer.pack_payload(name, data))
    assert (out_name, out_data) == (name, data)


def test_name_too_long_raises():
    with pytest.raises(PackError):
        packer.pack_payload("a" * (packer.MAX_NAME_LEN + 1), b"")


def test_unpack_truncated_payload_raises():
    with pytest.raises(PackError):
        packer.unpack_payload(b"\x00\x05ab")  # claims 5-byte name, has 2


def test_wrap_unwrap_round_trip():
    blob = b"encrypted-bytes"
    assert packer.unwrap(packer.wrap(blob)) == blob


def test_unwrap_bad_magic_raises():
    with pytest.raises(PackError):
        packer.unwrap(b"XXXX\x01payload")


def test_unwrap_too_short_raises():
    with pytest.raises(PackError):
        packer.unwrap(b"FV")


def test_unwrap_unsupported_version_raises():
    bad = packer.MAGIC + bytes([packer.VERSION + 1]) + b"data"
    with pytest.raises(PackError):
        packer.unwrap(bad)
