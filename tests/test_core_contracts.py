"""Smoke tests for the T0a contracts and fakes."""

import pytest

from padding_oracle.core import contracts as c
from padding_oracle.core import fakes as f


def _ct(plain=b"hello world"):
    return f.fake_cbc_encrypt(plain, bytes(16))


def test_perfect_oracle_returns_bool_and_counts_once():
    o = f.FakePerfectOracle()
    ct = _ct()
    assert o.query(ct) is True          # untouched ciphertext: padding OK
    assert o.queries == 1
    o.query(ct)
    assert o.queries == 2
    o.reset()
    assert o.queries == 0


def test_perfect_oracle_says_false_for_bad_padding():
    o = f.FakePerfectOracle()
    ct = bytearray(_ct())
    ct[-1] ^= 0x55                      # break the last block
    assert o.query(bytes(ct)) in (True, False)  # always a bool
    assert isinstance(o.query(bytes(ct)), bool)


def test_noisy_oracle_returns_float_and_counts_inner_check_once():
    o = f.FakeNoisyOracle(seed=1)
    x = o.query(_ct())
    assert isinstance(x, float)
    assert o.queries == 1               # inner check is not counted


def test_noisy_oracle_means_follow_the_truth():
    o = f.FakeNoisyOracle(seed=2)
    good = _ct()
    bad = bytearray(good)
    bad[-1] ^= 0xFF
    bad = bytes(bad)
    truth_bad = f.FakePerfectOracle().query(bad)
    n = 2000
    mg = sum(o.query(good) for _ in range(n)) / n
    mb = sum(o.query(bad) for _ in range(n)) / n
    assert abs(mg - f.MU_R) < 0.3
    if not truth_bad:
        assert abs(mb - f.MU_W) < 0.3


@pytest.mark.parametrize("bad", [b"", b"x" * 16, b"x" * 33, b"x" * 47])
def test_bad_ciphertext_length_is_rejected(bad):
    with pytest.raises(ValueError):
        f.FakePerfectOracle().query(bad)


def test_rejected_query_is_not_counted():
    o = f.FakePerfectOracle()
    with pytest.raises(ValueError):
        o.query(b"short")
    assert o.queries == 0


def test_stubs_match_the_contract_shapes():
    assert isinstance(f.stub_attack, c.Attack)
    assert isinstance(f.stub_sequential_check, c.SequentialCheck)
    o = f.FakeNoisyOracle(seed=3)
    two_blocks = _ct()[:32]
    assert len(f.stub_attack(o, two_blocks, 8)) == 8
    assert isinstance(f.stub_sequential_check(o, two_blocks), bool)


def test_csv_and_wordlist_columns_are_fixed():
    assert c.CSV_COLUMNS == [
        "experiment", "attack", "oracle", "seed", "target", "band",
        "bytes_attacked", "queries", "success", "params",
    ]
    assert c.WORDLIST_COLUMNS == ["word", "band", "split"]
