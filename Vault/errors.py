"""Exception hierarchy for File-Vault.

All errors raised by the library derive from :class:`VaultError`, so callers can
catch everything with a single ``except`` while still being able to distinguish
specific failures.
"""


class VaultError(Exception):
    """Base class for all File-Vault errors."""


class DecryptionError(VaultError):
    """Raised when a blob cannot be decrypted (wrong password or tampering)."""


class ContainerError(VaultError):
    """Raised when a vault container is malformed or its version unsupported."""


class ArchiveError(VaultError):
    """Raised when an archive is malformed or cannot be (un)packed."""


class PathTraversalError(ArchiveError):
    """Raised when an archive entry tries to escape the extraction directory."""


class OverwriteError(VaultError):
    """Raised when extraction would overwrite an existing file without consent."""
