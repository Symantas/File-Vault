import pytest

from Vault.container import VaultContainer
from Vault.errors import ContainerError


@pytest.fixture
def container():
    return VaultContainer()


def test_wrap_unwrap_round_trip(container):
    assert container.unwrap(container.wrap(b"blob")) == b"blob"


def test_header_is_magic_plus_version(container):
    assert container.header() == b"FVLT\x04"


def test_older_versions_rejected(container):
    # Clean break: v2 and v3 containers are no longer supported.
    for old in (b"FVLT\x02payload", b"FVLT\x03payload"):
        with pytest.raises(ContainerError):
            container.unwrap(old)


def test_bad_magic_raises(container):
    with pytest.raises(ContainerError):
        container.unwrap(b"XXXX\x02payload")


def test_too_short_raises(container):
    with pytest.raises(ContainerError):
        container.unwrap(b"FV")


def test_unsupported_version_raises(container):
    bad = VaultContainer.MAGIC + bytes([VaultContainer.VERSION + 1]) + b"data"
    with pytest.raises(ContainerError):
        container.unwrap(bad)
