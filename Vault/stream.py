"""Chunked authenticated encryption (the STREAM construction).

A payload is encrypted under a per-vault Data Encryption Key (DEK) as a sequence
of fixed-size AES-256-GCM chunks. This lets arbitrarily large inputs be processed
with O(chunk) memory instead of loading everything at once.

Security model (mirrors the age STREAM / libsodium ``secretstream`` design):

- The DEK is random and unique per vault, so a simple per-chunk counter is a safe
  GCM nonce — a (key, nonce) pair never repeats.
- Each chunk's nonce is ``counter (11 bytes, big-endian) || final_flag (1 byte)``.
  The counter binds chunk *order* (a chunk decrypted at the wrong index gets the
  wrong nonce/AAD and fails), and the final flag (``0x01`` on the last chunk only)
  detects truncation and extension.
- ``base_aad`` (supplied by the caller — the container header + chunk size) is
  folded into every chunk's AAD so the stream is bound to its container and a
  downgrade of either is rejected.
- An empty payload still emits a single ``final`` chunk, so a payload truncated to
  zero chunks is detectable.

On-the-wire each chunk is ``chunk_len (4 bytes, big-endian) | ciphertext+tag``.
"""

from collections.abc import Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import DecryptionError

CHUNK_PLAINTEXT = 64 * 1024  # 64 KiB plaintext per chunk
TAG_SIZE = 16
NONCE_SIZE = 12
_COUNTER_SIZE = NONCE_SIZE - 1  # 11 bytes; last nonce byte is the final flag
_MAX_COUNTER = (1 << (_COUNTER_SIZE * 8)) - 1
_LEN_SIZE = 4
_MAX_CHUNK_LEN = (1 << (_LEN_SIZE * 8)) - 1


def _nonce(counter: int, final: bool) -> bytes:
    return counter.to_bytes(_COUNTER_SIZE, "big") + (b"\x01" if final else b"\x00")


class ChunkStreamEncryptor:
    """Encrypts/decrypts a byte stream as authenticated fixed-size chunks."""

    def __init__(self, dek: bytes, chunk_size: int = CHUNK_PLAINTEXT) -> None:
        if chunk_size < 1 or chunk_size > CHUNK_PLAINTEXT * 1024:
            raise ValueError("unreasonable chunk size")
        self._aesgcm = AESGCM(dek)
        self._chunk_size = chunk_size

    @property
    def chunk_size(self) -> int:
        return self._chunk_size

    def encrypt_stream(
        self, plaintext_chunks: Iterator[bytes], base_aad: bytes
    ) -> Iterator[bytes]:
        """Yield length-prefixed ciphertext chunks for an iterator of plaintext.

        Input chunks of any size are regrouped into exact ``chunk_size`` chunks so
        the framing is independent of how the caller batches its bytes.
        """
        counter = 0
        # Peek-ahead buffering so we know which chunk is the last (final flag).
        pending = b""
        for piece in plaintext_chunks:
            pending += piece
            while len(pending) > self._chunk_size:
                block, pending = pending[: self._chunk_size], pending[self._chunk_size:]
                yield self._seal(counter, block, final=False, base_aad=base_aad)
                counter = self._next(counter)
        # The remainder (possibly empty) is the final chunk.
        yield self._seal(counter, pending, final=True, base_aad=base_aad)

    def decrypt_stream(
        self, cipher_chunks: Iterator[bytes], base_aad: bytes
    ) -> Iterator[bytes]:
        """Yield verified plaintext for an iterator of length-prefixed ciphertext.

        Raises :class:`DecryptionError` on any tampering, reordering, truncation,
        or trailing data after the final chunk.
        """
        counter = 0
        for ciphertext, final in _read_chunks(cipher_chunks):
            try:
                yield self._aesgcm.decrypt(
                    _nonce(counter, final), ciphertext, base_aad + _nonce(counter, final)
                )
            except InvalidTag as exc:
                raise DecryptionError(
                    "decryption failed: wrong key or corrupted data"
                ) from exc
            if final:
                return
            counter = self._next(counter)
        # Stream ended without a final-flagged chunk -> truncated.
        raise DecryptionError("encrypted stream is truncated (no final chunk)")

    def _seal(self, counter: int, block: bytes, final: bool, base_aad: bytes) -> bytes:
        nonce = _nonce(counter, final)
        ciphertext = self._aesgcm.encrypt(nonce, block, base_aad + nonce)
        return len(ciphertext).to_bytes(_LEN_SIZE, "big") + ciphertext

    @staticmethod
    def _next(counter: int) -> int:
        counter += 1
        if counter > _MAX_COUNTER:
            raise ValueError("payload too large: chunk counter overflow")
        return counter


def _read_chunks(cipher_chunks: Iterator[bytes]) -> Iterator[tuple[bytes, bool]]:
    """Reframe a raw byte iterator into ``(ciphertext, is_final)`` pairs.

    ``is_final`` is set on the chunk that turns out to be the last one in the
    stream. Bounds every length so a hostile length field cannot force a huge
    allocation. Raises :class:`DecryptionError` on malformed framing.
    """
    buffer = b""
    chunks = iter(cipher_chunks)
    exhausted = False

    def fill(n: int) -> bool:
        nonlocal buffer, exhausted
        while len(buffer) < n and not exhausted:
            try:
                buffer += next(chunks)
            except StopIteration:
                exhausted = True
        return len(buffer) >= n

    # One-chunk lookahead so the consumer can flag the final chunk.
    prev: bytes | None = None
    while True:
        if not fill(_LEN_SIZE):
            if buffer:
                raise DecryptionError("encrypted stream is truncated")
            break
        (length,) = (int.from_bytes(buffer[:_LEN_SIZE], "big"),)
        if length < TAG_SIZE or length > _MAX_CHUNK_LEN:
            raise DecryptionError("invalid encrypted chunk length")
        if not fill(_LEN_SIZE + length):
            raise DecryptionError("encrypted stream is truncated")
        ciphertext = buffer[_LEN_SIZE : _LEN_SIZE + length]
        buffer = buffer[_LEN_SIZE + length :]
        if prev is not None:
            yield prev, False
        prev = ciphertext
    if prev is not None:
        yield prev, True
