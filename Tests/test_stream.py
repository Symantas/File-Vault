import os

import pytest

from Vault.errors import DecryptionError
from Vault.stream import ChunkStreamEncryptor

AAD = b"FVLT\x04base"


@pytest.fixture
def enc():
    # Small chunk size so modest inputs span many chunks.
    return ChunkStreamEncryptor(os.urandom(32), chunk_size=64)


def _roundtrip(enc, plaintext):
    chunks = list(enc.encrypt_stream(iter([plaintext]), AAD))
    return b"".join(enc.decrypt_stream(iter(chunks), AAD)), chunks


def test_round_trip_single_chunk(enc):
    out, _ = _roundtrip(enc, b"hello world")
    assert out == b"hello world"


def test_round_trip_multi_chunk(enc):
    data = os.urandom(64 * 10 + 7)  # 10+ chunks
    out, chunks = _roundtrip(enc, data)
    assert out == data
    assert len(chunks) >= 10


def test_round_trip_empty(enc):
    out, chunks = _roundtrip(enc, b"")
    assert out == b""
    assert len(chunks) == 1  # a single final chunk over empty plaintext


def test_input_batching_is_irrelevant(enc):
    data = os.urandom(200)
    # Feed the plaintext in awkward little pieces; output must be identical-sized.
    chunks = list(enc.encrypt_stream(iter([data[i:i+3] for i in range(0, len(data), 3)]), AAD))
    assert b"".join(enc.decrypt_stream(iter(chunks), AAD)) == data


def test_tampered_chunk_raises(enc):
    _, chunks = _roundtrip(enc, os.urandom(200))
    blob = bytearray(b"".join(chunks))
    blob[-1] ^= 0xFF
    with pytest.raises(DecryptionError):
        list(enc.decrypt_stream(iter([bytes(blob)]), AAD))


def test_wrong_aad_raises(enc):
    _, chunks = _roundtrip(enc, b"secret data here")
    with pytest.raises(DecryptionError):
        list(enc.decrypt_stream(iter(chunks), AAD + b"x"))


def test_reordered_chunks_raise(enc):
    _, chunks = _roundtrip(enc, os.urandom(200))
    chunks[0], chunks[1] = chunks[1], chunks[0]
    with pytest.raises(DecryptionError):
        list(enc.decrypt_stream(iter(chunks), AAD))


def test_dropped_final_chunk_raises(enc):
    _, chunks = _roundtrip(enc, os.urandom(200))
    with pytest.raises(DecryptionError):
        list(enc.decrypt_stream(iter(chunks[:-1]), AAD))


def test_appended_chunk_after_final_raises(enc):
    _, chunks = _roundtrip(enc, os.urandom(200))
    with pytest.raises(DecryptionError):
        list(enc.decrypt_stream(iter(chunks + [chunks[-1]]), AAD))


def test_hostile_chunk_length_raises(enc):
    # Length prefix far larger than any legitimate chunk.
    blob = (0xFFFFFF).to_bytes(4, "big") + b"\x00" * 8
    with pytest.raises(DecryptionError):
        list(enc.decrypt_stream(iter([blob]), AAD))
