import pytest

from padding_oracle.tier1.aes import aes_cbc_encrypt
from padding_oracle.tier1.oracle import AESPerfectOracle

KEY = bytes(range(16))
IV = bytes(range(16, 32))


def test_oracle_reports_valid_padding_and_counts_queries():
    oracle = AESPerfectOracle(KEY)
    ciphertext = aes_cbc_encrypt(b"valid message", KEY, IV)

    assert oracle.query(ciphertext) is True
    assert oracle.queries == 1
    assert oracle.query(ciphertext) is True
    assert oracle.queries == 2


def test_oracle_returns_false_for_invalid_padding():
    oracle = AESPerfectOracle(KEY)
    ciphertext = bytearray(aes_cbc_encrypt(b"valid message", KEY, IV))
    ciphertext[-1] ^= 0x01

    assert oracle.query(bytes(ciphertext)) is False
    assert oracle.queries == 1


def test_oracle_reset_clears_counter():
    oracle = AESPerfectOracle(KEY)
    ciphertext = aes_cbc_encrypt(b"message", KEY, IV)
    oracle.query(ciphertext)
    oracle.reset()
    assert oracle.queries == 0


@pytest.mark.parametrize("ciphertext", [b"", b"x" * 16, b"x" * 31, b"x" * 33])
def test_malformed_ciphertext_is_rejected_without_counting(ciphertext):
    oracle = AESPerfectOracle(KEY)
    with pytest.raises((TypeError, ValueError)):
        oracle.query(ciphertext)
    assert oracle.queries == 0


@pytest.mark.parametrize("key", [b"short", b"x" * 20])
def test_oracle_rejects_invalid_key(key):
    with pytest.raises(ValueError):
        AESPerfectOracle(key)


def test_pycryptodome_aes_module_exposes_gcm_mode():
    from Crypto.Cipher import AES
    assert hasattr(AES, "MODE_GCM")
