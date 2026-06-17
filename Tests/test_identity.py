import pytest

from Vault.identity import Identity, IdentityError, Recipient


def test_identity_recipient_round_trip():
    identity = Identity.generate()
    recipient = identity.recipient()
    assert Recipient.parse(recipient.encode()).public_bytes == recipient.public_bytes


def test_identity_encode_parse_round_trip():
    identity = Identity.generate()
    reparsed = Identity.parse(identity.encode())
    # Same private key derives the same shared secret for a given peer.
    peer = Identity.generate().recipient().public_bytes
    assert reparsed.exchange(peer) == identity.exchange(peer)


def test_load_from_file(tmp_path):
    identity = Identity.generate()
    path = tmp_path / "id.key"
    path.write_text("# a comment\n" + identity.encode() + "\n")
    loaded = Identity.load(str(path))
    assert loaded.recipient().public_bytes == identity.recipient().public_bytes


def test_recipient_bad_prefix_rejected():
    with pytest.raises(IdentityError):
        Recipient.parse("not-a-key")


def test_secret_prefix_not_accepted_as_recipient():
    secret = Identity.generate().encode()
    with pytest.raises(IdentityError):
        Recipient.parse(secret)


def test_exchange_is_symmetric():
    a, b = Identity.generate(), Identity.generate()
    assert a.exchange(b.recipient().public_bytes) == b.exchange(a.recipient().public_bytes)
