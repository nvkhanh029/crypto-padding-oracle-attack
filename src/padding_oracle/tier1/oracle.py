"""Real AES-CBC perfect padding oracle for Tier 1."""

from __future__ import annotations

from padding_oracle.core.contracts import PerfectOracle
from .aes import aes_cbc_decrypt_raw, pkcs7_padding_ok


class AESPerfectOracle(PerfectOracle):
    """Reveal only whether AES-CBC plaintext has valid PKCS#7 padding.

    Query validation and the exact-once query counter are inherited from
    core.contracts.PerfectOracle / BaseOracle.
    """

    def __init__(self, key: bytes) -> None:
        super().__init__()
        if not isinstance(key, bytes):
            raise TypeError("key must be bytes")
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24, or 32 bytes")
        self._key = key

    def _answer(self, ciphertext: bytes) -> bool:
        plaintext = aes_cbc_decrypt_raw(ciphertext, self._key)
        return pkcs7_padding_ok(plaintext)
