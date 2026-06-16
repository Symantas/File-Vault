"""High-level file operations for File-Vault.

These helpers combine :mod:`Vault.encryption` and :mod:`Vault.packer` to turn a
file on disk into an encrypted ``.vault`` container and back again.
"""

import os

from . import encryption, packer

VAULT_SUFFIX = ".vault"


def encrypt_file(source: str, password: str, destination: str | None = None) -> str:
    """Encrypt ``source`` into a vault container.

    The original file name is stored *inside* the encrypted payload. If
    ``destination`` is omitted, ``<source>.vault`` is used.

    Returns the path of the written container.
    """
    with open(source, "rb") as fh:
        data = fh.read()

    payload = packer.pack_payload(os.path.basename(source), data)
    blob = encryption.encrypt(payload, password)
    container = packer.wrap(blob)

    if destination is None:
        destination = source + VAULT_SUFFIX

    with open(destination, "wb") as fh:
        fh.write(container)
    return destination


def decrypt_file(source: str, password: str, destination: str | None = None) -> str:
    """Decrypt a vault ``source`` back to its original contents.

    If ``destination`` is omitted, the file is restored next to ``source`` using
    the original name stored in the container.

    Returns the path of the written file.
    """
    with open(source, "rb") as fh:
        container = fh.read()

    blob = packer.unwrap(container)
    payload = encryption.decrypt(blob, password)
    original_name, data = packer.unpack_payload(payload)

    if destination is None:
        destination = os.path.join(os.path.dirname(source), original_name)

    with open(destination, "wb") as fh:
        fh.write(data)
    return destination
