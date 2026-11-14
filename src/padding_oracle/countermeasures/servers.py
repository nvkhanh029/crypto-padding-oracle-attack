"""Authenticated server models that do not expose CBC padding validity."""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..core.contracts import BLOCK_SIZE, BaseOracle

_AUTHENTICATION_ERROR = "authentication failed"
_GCM_NONCE_SIZE = 12
_GCM_TAG_SIZE = 16


class AuthenticationError(ValueError):
    """Uniform public rejection for invalid authenticated ciphertexts."""

    def __init__(self) -> None:
        super().__init__(_AUTHENTICATION_ERROR)


@dataclass(frozen=True)
class Envelope:
    """Ciphertext and its authentication tag."""

    ciphertext: bytes
    tag: bytes


def _validate_aes_key(key: bytes) -> None:
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")


class EncryptThenMacServer:
    """AES-CBC Encrypt-then-MAC with HMAC verified before decryption."""

    def __init__(self, encryption_key: bytes, mac_key: bytes) -> None:
        _validate_aes_key(encryption_key)
        if len(mac_key) < 16:
            raise ValueError("MAC key must be at least 16 bytes")
        self._encryption_key = bytes(encryption_key)
        self._mac_key = bytes(mac_key)

    def seal(self, plaintext: bytes, iv: bytes | None = None) -> Envelope:
        iv = os.urandom(BLOCK_SIZE) if iv is None else bytes(iv)
        if len(iv) != BLOCK_SIZE:
            raise ValueError("CBC IV must be 16 bytes")

        padder = padding.PKCS7(BLOCK_SIZE * 8).padder()
        padded = padder.update(plaintext) + padder.finalize()
        encryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CBC(iv)
        ).encryptor()
        ciphertext = iv + encryptor.update(padded) + encryptor.finalize()
        tag = hmac.digest(self._mac_key, ciphertext, hashlib.sha256)
        return Envelope(ciphertext, tag)

    def open(self, ciphertext: bytes, tag: bytes) -> bytes:
        ciphertext = bytes(ciphertext)
        tag = bytes(tag)
        if len(ciphertext) < 2 * BLOCK_SIZE or len(ciphertext) % BLOCK_SIZE:
            raise AuthenticationError()

        expected_tag = hmac.digest(self._mac_key, ciphertext, hashlib.sha256)
        if not hmac.compare_digest(expected_tag, tag):
            raise AuthenticationError()

        return self._decrypt(ciphertext)

    def _decrypt(self, ciphertext: bytes) -> bytes:
        iv, body = ciphertext[:BLOCK_SIZE], ciphertext[BLOCK_SIZE:]
        decryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CBC(iv)
        ).decryptor()
        padded = decryptor.update(body) + decryptor.finalize()
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        try:
            return unpadder.update(padded) + unpadder.finalize()
        except ValueError as error:
            raise AuthenticationError() from error

    def oracle_for(self, envelope: Envelope) -> EncryptThenMacOracle:
        """Bind an oracle adapter to the tag captured with a challenge."""
        if len(envelope.ciphertext) != 2 * BLOCK_SIZE:
            raise ValueError("attack oracle requires a two-block challenge")
        return EncryptThenMacOracle(self, envelope.tag)


class EncryptThenMacOracle(BaseOracle):
    """Challenge-bound adapter that reuses the captured authentication tag."""

    def __init__(self, server: EncryptThenMacServer, captured_tag: bytes) -> None:
        super().__init__()
        self._server = server
        self._captured_tag = bytes(captured_tag)

    def _answer(self, ciphertext: bytes) -> bool:
        try:
            self._server.open(ciphertext, self._captured_tag)
        except AuthenticationError:
            return False
        return True


class AesGcmServer:
    """AES-GCM authenticated-encryption server with uniform tag rejection."""

    def __init__(self, key: bytes) -> None:
        _validate_aes_key(key)
        self._aead = AESGCM(bytes(key))

    def seal(
        self,
        plaintext: bytes,
        nonce: bytes | None = None,
        associated_data: bytes | None = None,
    ) -> Envelope:
        nonce = os.urandom(_GCM_NONCE_SIZE) if nonce is None else bytes(nonce)
        if len(nonce) != _GCM_NONCE_SIZE:
            raise ValueError("AES-GCM nonce must be 12 bytes")
        sealed = self._aead.encrypt(nonce, plaintext, associated_data)
        return Envelope(nonce + sealed[:-_GCM_TAG_SIZE], sealed[-_GCM_TAG_SIZE:])

    def open(
        self,
        ciphertext: bytes,
        tag: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        ciphertext = bytes(ciphertext)
        tag = bytes(tag)
        if len(ciphertext) < _GCM_NONCE_SIZE or len(tag) != _GCM_TAG_SIZE:
            raise AuthenticationError()

        nonce = ciphertext[:_GCM_NONCE_SIZE]
        body = ciphertext[_GCM_NONCE_SIZE:]
        try:
            return self._aead.decrypt(nonce, body + tag, associated_data)
        except (InvalidTag, ValueError) as error:
            raise AuthenticationError() from error

    def oracle_for(
        self,
        envelope: Envelope,
        associated_data: bytes | None = None,
    ) -> AesGcmOracle:
        """Bind an oracle adapter to the tag captured with a challenge."""
        if len(envelope.ciphertext) != 2 * BLOCK_SIZE:
            raise ValueError("plaintext must be 20 bytes so nonce + ciphertext = 32 bytes")
        return AesGcmOracle(self, envelope.tag, associated_data)


class AesGcmOracle(BaseOracle):
    """Challenge-bound adapter exposing only authenticated acceptance."""

    def __init__(
        self,
        server: AesGcmServer,
        captured_tag: bytes,
        associated_data: bytes | None = None,
    ) -> None:
        super().__init__()
        self._server = server
        self._captured_tag = bytes(captured_tag)
        self._associated_data = associated_data

    def _answer(self, ciphertext: bytes) -> bool:
        try:
            self._server.open(
                ciphertext, self._captured_tag, self._associated_data
            )
        except AuthenticationError:
            return False
        return True
