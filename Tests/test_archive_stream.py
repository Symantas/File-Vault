import os

import pytest

from Vault.archive import CONTENT_CHUNK, DirectoryArchiver


@pytest.fixture
def archiver():
    return DirectoryArchiver()


def test_pack_stream_is_lazy_and_chunked(archiver, tmp_path):
    big = tmp_path / "big.bin"
    big.write_bytes(os.urandom(CONTENT_CHUNK * 3 + 100))
    pieces = list(archiver.pack_stream(str(big)))
    # A multi-chunk file yields several pieces, not one giant blob.
    assert len(pieces) > 3


def test_streaming_round_trip_large_file(archiver, tmp_path):
    src = tmp_path / "big.bin"
    blob = os.urandom(CONTENT_CHUNK * 4 + 1234)
    src.write_bytes(blob)

    stream = archiver.pack_stream(str(src))
    dest = tmp_path / "out"
    written = archiver.unpack_stream(stream, str(dest))
    assert written == [str(dest / "big.bin")]
    assert (dest / "big.bin").read_bytes() == blob


def test_streaming_round_trip_tree(archiver, tmp_path):
    root = tmp_path / "tree"
    (root / "sub").mkdir(parents=True)
    (root / "a.bin").write_bytes(os.urandom(CONTENT_CHUNK + 5))
    (root / "sub" / "b.txt").write_bytes(b"small")

    dest = tmp_path / "out"
    archiver.unpack_stream(archiver.pack_stream(str(root)), str(dest))
    assert (dest / "tree" / "a.bin").read_bytes() == (root / "a.bin").read_bytes()
    assert (dest / "tree" / "sub" / "b.txt").read_bytes() == b"small"


def test_unpack_stream_consumes_iterator_in_pieces(archiver, tmp_path):
    src = tmp_path / "f.txt"
    src.write_bytes(b"streamed bytes")
    # Re-feed the packed bytes one byte at a time to prove the reader reassembles.
    packed = archiver.pack(str(src))
    dest = tmp_path / "out"
    archiver.unpack_stream(iter([packed[i:i+1] for i in range(len(packed))]), str(dest))
    assert (dest / "f.txt").read_bytes() == b"streamed bytes"
