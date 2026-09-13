import struct

import pytest

from Vault.archive import (
    RECORD_DIR,
    RECORD_END,
    RECORD_FILE,
    DirectoryArchiver,
)
from Vault.errors import ArchiveError, OverwriteError, PathTraversalError


@pytest.fixture
def archiver():
    return DirectoryArchiver()


def test_single_file_round_trip(archiver, tmp_path):
    src = tmp_path / "note.txt"
    src.write_bytes(b"hello")
    data = archiver.pack(str(src))

    dest = tmp_path / "out"
    written = archiver.unpack(data, str(dest))
    assert written == [str(dest / "note.txt")]
    assert (dest / "note.txt").read_bytes() == b"hello"


def test_directory_tree_round_trip(archiver, tmp_path):
    root = tmp_path / "project"
    (root / "sub").mkdir(parents=True)
    (root / "a.txt").write_bytes(b"A")
    (root / "sub" / "b.txt").write_bytes(b"B")
    (root / "empty").mkdir()

    data = archiver.pack(str(root))
    dest = tmp_path / "out"
    archiver.unpack(data, str(dest))

    assert (dest / "project" / "a.txt").read_bytes() == b"A"
    assert (dest / "project" / "sub" / "b.txt").read_bytes() == b"B"
    assert (dest / "project" / "empty").is_dir()


def test_overwrite_protection(archiver, tmp_path):
    src = tmp_path / "f.txt"
    src.write_bytes(b"new")
    data = archiver.pack(str(src))

    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "f.txt").write_bytes(b"old")

    with pytest.raises(OverwriteError):
        archiver.unpack(data, str(dest))
    assert (dest / "f.txt").read_bytes() == b"old"  # untouched

    archiver.unpack(data, str(dest), overwrite=True)
    assert (dest / "f.txt").read_bytes() == b"new"


def test_pack_missing_source_raises(archiver, tmp_path):
    with pytest.raises(ArchiveError):
        archiver.pack(str(tmp_path / "nope"))


def test_pack_refuses_symlink(archiver, tmp_path):
    target = tmp_path / "real.txt"
    target.write_bytes(b"x")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    with pytest.raises(ArchiveError):
        archiver.pack(str(link))


def test_skips_symlinks_inside_tree(archiver, tmp_path):
    root = tmp_path / "d"
    root.mkdir()
    (root / "real.txt").write_bytes(b"r")
    (root / "link.txt").symlink_to(tmp_path / "real.txt")

    data = archiver.pack(str(root))
    dest = tmp_path / "out"
    archiver.unpack(data, str(dest))
    assert (dest / "d" / "real.txt").exists()
    assert not (dest / "d" / "link.txt").exists()


# --- security: malicious archive payloads -------------------------------

def _file_record(path: str, content: bytes) -> bytes:
    enc = path.encode("utf-8")
    return (
        bytes([RECORD_FILE]) + struct.pack(">H", len(enc)) + enc
        + struct.pack(">I", len(content)) + content
        + struct.pack(">I", 0)  # end of content
    )


@pytest.mark.parametrize(
    "evil_path",
    [
        "../escape.txt",
        "../../escape.txt",
        "sub/../../escape.txt",
        "/etc/passwd",
        "a/./../../escape.txt",
        "a\\..\\escape.txt",
    ],
)
def test_path_traversal_blocked(archiver, tmp_path, evil_path):
    blob = _file_record(evil_path, b"pwned") + bytes([RECORD_END])
    with pytest.raises(PathTraversalError):
        archiver.unpack(blob, str(tmp_path / "out"))
    assert not (tmp_path / "escape.txt").exists()


def test_truncated_archive_raises(archiver, tmp_path):
    # A file record whose content run is cut off, with no END marker.
    enc = b"x.txt"
    blob = bytes([RECORD_FILE]) + struct.pack(">H", len(enc)) + enc + struct.pack(">I", 100)
    with pytest.raises(ArchiveError):
        archiver.unpack(blob, str(tmp_path / "out"))


def test_missing_end_marker_raises(archiver, tmp_path):
    blob = _file_record("ok.txt", b"data")[: -1]  # drop the END... actually no END appended
    blob = _file_record("ok.txt", b"data")  # complete file record, but no END
    with pytest.raises(ArchiveError):
        archiver.unpack(blob, str(tmp_path / "out"))


def test_oversized_data_run_rejected(archiver, tmp_path):
    enc = b"big.bin"
    blob = (
        bytes([RECORD_FILE]) + struct.pack(">H", len(enc)) + enc
        + struct.pack(">I", 0xFFFFFFFF)  # absurd declared run
    )
    with pytest.raises(ArchiveError):
        archiver.unpack(blob, str(tmp_path / "out"))
