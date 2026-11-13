"""Tests for the Tier 1 Vaudenay attack using the real AES padding oracle."""

import pytest

from padding_oracle.tier1.aes import aes_cbc_encrypt
from padding_oracle.tier1.attack import attack
from padding_oracle.tier1.oracle import AESPerfectOracle


TEST_KEY = bytes.fromhex("00112233445566778899aabbccddeeff")


def make_challenge(plaintext: bytes, iv: bytes) -> bytes:
    """Encrypt plaintext and return the IV plus its first ciphertext block."""
    return aes_cbc_encrypt(plaintext, TEST_KEY, iv)[:32]


def test_vaudenay_attack_recovers_all_16_bytes():
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    iv = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    challenge = make_challenge(plaintext, iv)

    oracle = AESPerfectOracle(TEST_KEY)
    assert attack(oracle, challenge, 16) == plaintext
    assert oracle.queries > 0


def test_attack_records_per_byte_query_deltas():
    plaintext = bytes(range(16))
    iv = bytes(reversed(range(16)))
    challenge = make_challenge(plaintext, iv)
    oracle = AESPerfectOracle(TEST_KEY)
    counts = []

    assert attack(oracle, challenge, 16, byte_query_counts=counts) == plaintext
    assert len(counts) == 16
    assert all(count > 0 for count in counts)
    assert sum(counts) == oracle.queries


def test_attack_requires_exactly_two_blocks():
    oracle = AESPerfectOracle(TEST_KEY)
    with pytest.raises(ValueError, match="exactly two"):
        attack(oracle, bytes(48), 16)


def test_attack_rejects_invalid_byte_count():
    plaintext = bytes(range(16))
    iv = bytes(16)
    challenge = make_challenge(plaintext, iv)
    oracle = AESPerfectOracle(TEST_KEY)

    with pytest.raises(ValueError, match="between 1 and 16"):
        attack(oracle, challenge, 17)


def test_vaudenay_attack_recovers_last_8_bytes_for_d15_layout():
    # D15 layout: 8-byte prefix followed by an 8-digit word.
    plaintext = b"PREFIX!!12345678"
    iv = bytes(16)
    challenge = make_challenge(plaintext, iv)

    recovered = attack(AESPerfectOracle(TEST_KEY), challenge, 8)

    assert recovered == b"12345678"
    assert len(recovered) == 8


def test_vaudenay_attack_rejects_accidental_valid_0202_padding():
    # The original plaintext ends in valid PKCS#7 padding (02 02).
    # The attack must confirm the last-byte candidate rather than accept
    # the original plaintext's padding as the crafted 01-padding response.
    plaintext = bytes(14) + b"\x02\x02"
    iv = bytes(16)
    challenge = make_challenge(plaintext, iv)

    assert attack(AESPerfectOracle(TEST_KEY), challenge, 16) == plaintext

