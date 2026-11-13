import pytest

from padding_oracle.tier1.aes import (
    aes_cbc_decrypt,
    aes_cbc_decrypt_raw,
    aes_cbc_encrypt,
    pkcs7_pad,
    pkcs7_padding_ok,
    pkcs7_unpad,
)

KEY = bytes(range(16))
IV = bytes(range(16, 32))


@pytest.mark.parametrize(
    "plaintext",
    [
        b"",
        b"hello",
        b"x" * 15,
        b"x" * 16,
        b"x" * 32,
        bytes(range(255)),
    ],
)
def test_aes_cbc_round_trip(plaintext):
    ciphertext = aes_cbc_encrypt(plaintext, KEY, IV)
    assert len(ciphertext) >= 32
    assert len(ciphertext) % 16 == 0
    assert ciphertext[:16] == IV
    assert aes_cbc_decrypt(ciphertext, KEY) == plaintext


def test_pkcs7_adds_full_block_for_aligned_input():
    padded = pkcs7_pad(b"x" * 16)
    assert len(padded) == 32
    assert padded[-16:] == bytes([16]) * 16


def test_pkcs7_unpad_rejects_invalid_padding():
    assert not pkcs7_padding_ok(b"x" * 16 + b"\x02\x03")
    with pytest.raises(ValueError):
        pkcs7_unpad(b"x" * 15 + b"\x00")


def test_raw_decrypt_preserves_padding():
    ciphertext = aes_cbc_encrypt(b"hello", KEY, IV)
    raw = aes_cbc_decrypt_raw(ciphertext, KEY)
    assert raw == b"hello" + bytes([11]) * 11


@pytest.mark.parametrize("key", [b"short", b"x" * 20])
def test_rejects_invalid_aes_key(key):
    with pytest.raises(ValueError):
        aes_cbc_encrypt(b"data", key, IV)


def test_rejects_invalid_iv():
    with pytest.raises(ValueError):
        aes_cbc_encrypt(b"data", KEY, b"short")
