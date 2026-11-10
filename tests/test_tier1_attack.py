from padding_oracle.core.fakes import FakePerfectOracle, fake_cbc_encrypt
from padding_oracle.tier1.attack import attack


def test_vaudenay_attack_recovers_all_16_bytes():
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    iv = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    challenge = fake_cbc_encrypt(plaintext, iv)[:32]

    oracle = FakePerfectOracle()
    assert attack(oracle, challenge, 16) == plaintext
    assert oracle.queries > 0


def test_attack_records_per_byte_query_deltas():
    plaintext = bytes(range(16))
    iv = bytes(reversed(range(16)))
    challenge = fake_cbc_encrypt(plaintext, iv)[:32]
    oracle = FakePerfectOracle()
    counts = []

    assert attack(oracle, challenge, 16, byte_query_counts=counts) == plaintext
    assert len(counts) == 16
    assert all(count > 0 for count in counts)
    assert sum(counts) == oracle.queries


def test_attack_requires_exactly_two_blocks():
    import pytest
    with pytest.raises(ValueError, match="exactly two"):
        attack(FakePerfectOracle(), bytes(48), 16)


def test_attack_rejects_invalid_byte_count():
    import pytest
    with pytest.raises(ValueError, match="between 1 and 16"):
        attack(FakePerfectOracle(), bytes(32), 17)
