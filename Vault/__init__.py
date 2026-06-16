"""File-Vault: password-based encryption of files and folders (AES-256-GCM)."""

from .archive import Archiver, DirectoryArchiver
from .cipher import AesGcmEncryptor, Encryptor
from .container import VaultContainer
from .errors import (
    ArchiveError,
    ContainerError,
    DecryptionError,
    OverwriteError,
    PathTraversalError,
    VaultError,
)
from .kdf import KeyDerivation, PBKDF2KeyDerivation
from .service import VAULT_SUFFIX, VaultService

__all__ = [
    "Archiver",
    "DirectoryArchiver",
    "AesGcmEncryptor",
    "Encryptor",
    "VaultContainer",
    "KeyDerivation",
    "PBKDF2KeyDerivation",
    "VaultService",
    "VAULT_SUFFIX",
    "VaultError",
    "DecryptionError",
    "ContainerError",
    "ArchiveError",
    "PathTraversalError",
    "OverwriteError",
]
__version__ = "0.2.0"
