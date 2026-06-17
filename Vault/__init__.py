"""File-Vault: password-based encryption of files and folders (AES-256-GCM)."""

from .archive import Archiver, DirectoryArchiver
from .cipher import AesGcmEncryptor, Encryptor
from .container import Container, VaultContainer
from .errors import (
    ArchiveError,
    ContainerError,
    DecryptionError,
    OverwriteError,
    PathTraversalError,
    SlotError,
    VaultError,
)
from .kdf import (
    KdfParams,
    KeyDerivation,
    PBKDF2KeyDerivation,
    ScryptKeyDerivation,
)
from .identity import Identity, IdentityError, Recipient
from .slots import DEK_SIZE, KeySlot, PasswordSlot, RecipientSlot
from .stream import ChunkStreamEncryptor
from .service import VAULT_SUFFIX, SlotInfo, VaultInfo, VaultService

__all__ = [
    "Archiver",
    "DirectoryArchiver",
    "AesGcmEncryptor",
    "Encryptor",
    "Container",
    "VaultContainer",
    "KdfParams",
    "KeyDerivation",
    "PBKDF2KeyDerivation",
    "ScryptKeyDerivation",
    "KeySlot",
    "PasswordSlot",
    "RecipientSlot",
    "Identity",
    "Recipient",
    "IdentityError",
    "DEK_SIZE",
    "ChunkStreamEncryptor",
    "VaultService",
    "VaultInfo",
    "SlotInfo",
    "VAULT_SUFFIX",
    "VaultError",
    "DecryptionError",
    "ContainerError",
    "ArchiveError",
    "PathTraversalError",
    "OverwriteError",
    "SlotError",
]
__version__ = "0.4.0"
