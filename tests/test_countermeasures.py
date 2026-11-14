import hashlib
import hmac
from unittest.mock import Mock

import pytest

from padding_oracle.countermeasures import (
    AesGcmServer,
    AuthenticationError,
    EncryptThenMacServer,
)
from padding_oracle.tier1.attack import attack


def _authentication_error_message(call):
    with pytest.raises(AuthenticationError) as error:
        call()
    return str(error.value)


def test_encrypt_then_mac_authenticates_before_decrypting(monkeypatch):
    server = EncryptThenMacServer(bytes(16), bytes(range(32)))
    envelope = server.seal(b"secret", iv=bytes(16))
    decrypt = Mock(side_effect=AssertionError("decryption ran before MAC check"))
    monkeypatch.setattr(server, "_decrypt", decrypt)
    tampered = bytearray(envelope.ciphertext)
    tampered[0] ^= 1

    assert _authentication_error_message(
        lambda: server.open(bytes(tampered), envelope.tag)
    ) == "authentication failed"
    decrypt.assert_not_called()


def test_encrypt_then_mac_uses_one_error_for_invalid_requests():
    mac_key = bytes(range(32))
    server = EncryptThenMacServer(bytes(16), mac_key)
    envelope = server.seal(b"", iv=bytes(16))
    bad_padding = bytearray(envelope.ciphertext)
    bad_padding[15] ^= 1
    valid_mac_for_bad_padding = hmac.digest(
        mac_key, bad_padding, hashlib.sha256
    )

    errors = [
        _authentication_error_message(
            lambda: server.open(b"short", envelope.tag)
        ),
        _authentication_error_message(
            lambda: server.open(envelope.ciphertext, b"wrong")
        ),
        _authentication_error_message(
            lambda: server.open(bytes(bad_padding), valid_mac_for_bad_padding)
        ),
    ]

    assert errors == ["authentication failed"] * 3


def test_aes_gcm_uses_one_error_for_invalid_requests():
    server = AesGcmServer(bytes(16))
    envelope = server.seal(b"authenticated", nonce=bytes(12))
    bad_ciphertext = bytearray(envelope.ciphertext)
    bad_ciphertext[-1] ^= 1

    errors = [
        _authentication_error_message(
            lambda: server.open(b"short", envelope.tag)
        ),
        _authentication_error_message(
            lambda: server.open(envelope.ciphertext, b"wrong")
        ),
        _authentication_error_message(
            lambda: server.open(bytes(bad_ciphertext), envelope.tag)
        ),
    ]

    assert errors == ["authentication failed"] * 3


@pytest.mark.parametrize(
    ("server_type", "args"),
    [
        (EncryptThenMacServer, (b"secret", bytes(32))),
        (AesGcmServer, (b"secret",)),
    ],
)
def test_servers_reject_invalid_aes_key_size(server_type, args):
    with pytest.raises(ValueError, match="AES key must be 16, 24, or 32 bytes"):
        server_type(*args)


def _assert_single_byte_tampering_is_rejected(server, envelope):
    oracle = server.oracle_for(envelope)
    assert oracle.query(envelope.ciphertext) is True

    for index in range(len(envelope.ciphertext)):
        tampered = bytearray(envelope.ciphertext)
        tampered[index] ^= 1
        assert oracle.query(bytes(tampered)) is False

    assert oracle.queries == len(envelope.ciphertext) + 1


def test_etm_oracle_rejects_all_single_byte_tampering():
    server = EncryptThenMacServer(bytes(16), bytes(range(32)))
    envelope = server.seal(b"", iv=bytes(16))

    _assert_single_byte_tampering_is_rejected(server, envelope)


def test_gcm_oracle_rejects_all_single_byte_tampering():
    server = AesGcmServer(bytes(16))
    envelope = server.seal(b"x" * 20, nonce=bytes(12))

    _assert_single_byte_tampering_is_rejected(server, envelope)


def test_tier1_attack_fails_against_encrypt_then_mac():
    server = EncryptThenMacServer(bytes(16), bytes(range(32)))
    envelope = server.seal(b"secret", iv=bytes(16))
    oracle = server.oracle_for(envelope)
    assert oracle.query(envelope.ciphertext) is True
    oracle.reset()

    with pytest.raises(RuntimeError, match="could not recover plaintext byte"):
        attack(oracle, envelope.ciphertext, 16)

    assert oracle.queries >= 256


def test_tier1_attack_fails_against_aes_gcm():
    server = AesGcmServer(bytes(16))
    envelope = server.seal(b"x" * 20, nonce=bytes(12))
    oracle = server.oracle_for(envelope)
    assert oracle.query(envelope.ciphertext) is True
    oracle.reset()

    with pytest.raises(RuntimeError, match="could not recover plaintext byte"):
        attack(oracle, envelope.ciphertext, 16)

    assert oracle.queries >= 256
