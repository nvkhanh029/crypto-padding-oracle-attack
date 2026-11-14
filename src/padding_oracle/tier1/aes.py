"""AES-CBC and PKCS#7 helpers used by Tier 1.

Ciphertexts use the repository convention: IV || ciphertext blocks.
PyCryptodome is required: pip install pycryptodome
"""

from __future__ import annotations

from Crypto.Cipher import AES

from padding_oracle.core.contracts import BLOCK_SIZE, validate_ciphertext


def _require_bytes(name: str, value: bytes) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")


def _validate_key(key: bytes) -> None:
    _require_bytes("key", key)
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")


def _validate_iv(iv: bytes) -> None:
    _require_bytes("iv", iv)
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"iv must be exactly {BLOCK_SIZE} bytes")


def pkcs7_pad(data: bytes) -> bytes:
    """Apply PKCS#7 padding, including a full block when already aligned."""
    _require_bytes("data", data)
    padding_length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding_length]) * padding_length


def pkcs7_padding_ok(data: bytes) -> bool:
    """Return whether data ends in a complete, valid PKCS#7 padding suffix."""
    if not isinstance(data, bytes) or not data or len(data) % BLOCK_SIZE != 0:
        return False

    padding_length = data[-1]
    if not 1 <= padding_length <= BLOCK_SIZE:
        return False

    expected = bytes([padding_length]) * padding_length
    return data[-padding_length:] == expected


def pkcs7_unpad(data: bytes) -> bytes:
    """Remove valid PKCS#7 padding or raise ValueError."""
    _require_bytes("data", data)
    if not pkcs7_padding_ok(data):
        raise ValueError("invalid PKCS#7 padding")
    return data[:-data[-1]]


def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Pad and AES-CBC-encrypt plaintext; return IV || ciphertext."""
    _require_bytes("plaintext", plaintext)
    _validate_key(key)
    _validate_iv(iv)

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    encrypted = cipher.encrypt(pkcs7_pad(plaintext))
    return iv + encrypted


def aes_cbc_decrypt_raw(ciphertext: bytes, key: bytes) -> bytes:
    """AES-CBC-decrypt IV || ciphertext without removing padding."""
    _validate_key(key)
    validate_ciphertext(ciphertext)

    iv = ciphertext[:BLOCK_SIZE]
    encrypted = ciphertext[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return cipher.decrypt(encrypted)


def aes_cbc_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """AES-CBC-decrypt IV || ciphertext and remove PKCS#7 padding."""
    return pkcs7_unpad(aes_cbc_decrypt_raw(ciphertext, key))
