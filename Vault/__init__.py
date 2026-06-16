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
    VaultError,
)
from .kdf import (
    KdfParams,
    KeyDerivation,
    PBKDF2KeyDerivation,
    ScryptKeyDerivation,
)
from .service import VAULT_SUFFIX, VaultInfo, VaultService

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
    "VaultService",
    "VaultInfo",
    "VAULT_SUFFIX",
    "VaultError",
    "DecryptionError",
    "ContainerError",
    "ArchiveError",
    "PathTraversalError",
    "OverwriteError",
]
__version__ = "0.3.0"
