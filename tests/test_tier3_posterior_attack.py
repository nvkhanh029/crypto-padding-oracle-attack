"""Smoke tests for the posterior-threshold attack (T10), on the fake noisy oracle."""

import pytest

from padding_oracle.core import fakes as f
from padding_oracle.tier3.posterior_attack import (
    MU_R,
    MU_W,
    posterior_attack,
    timing_llr,
)

PREFIX = b"prefix00"          # known 8-byte prefix (D15)


def two_blocks(plain16: bytes) -> bytes:
    """IV + the target block for a 16-byte plaintext."""
    return f.fake_cbc_encrypt(plain16, bytes(16))[:32]


def prior_favouring(word: bytes, p_right: float):
    """A test prior that gives probability p_right to the right next byte.

    It knows the answer, so it only shows that the prior is used; it is not
    a realistic prior (that is T9's trigram).
    """
    def prior(suffix: bytes) -> list[float]:
        right = word[len(word) - 1 - len(suffix)]
        probs = [(1 - p_right) / 255] * 256
        probs[right] = p_right
        return probs
    return prior


def test_recovers_word_with_uniform_prior():
    oracle = f.FakeNoisyOracle(seed=1)
    got = posterior_attack(oracle, two_blocks(PREFIX + b"password"), 8, seed=1)
    assert got == b"password"


def test_last_byte_trap_block_is_recovered():
    # Byte 15 is 0x02: with fixed bytes on the left, a wrong last-byte guess
    # would give the valid padding 02 02 every time. Random left bytes stop it.
    plain = b"0123456789abcd\x02C"
    oracle = f.FakeNoisyOracle(seed=2)
    assert posterior_attack(oracle, two_blocks(plain), 16, seed=2) == plain


def test_sure_prior_accepts_without_queries():
    # Prior above 1 - delta: the posterior already passes, so no query is
    # needed. This shows the prior is inside the decision rule.
    oracle = f.FakeNoisyOracle(seed=3)
    prior = prior_favouring(b"password", 0.9999)
    got = posterior_attack(oracle, two_blocks(PREFIX + b"password"), 8,
                           prior=prior)
    assert got == b"password"
    assert oracle.queries == 0


def test_good_prior_needs_fewer_queries_than_uniform():
    ct = two_blocks(PREFIX + b"password")
    uniform = f.FakeNoisyOracle(seed=4)
    guided = f.FakeNoisyOracle(seed=4)
    assert posterior_attack(uniform, ct, 8, seed=4) == b"password"
    assert posterior_attack(guided, ct, 8, seed=4,
                            prior=prior_favouring(b"password", 0.5)) == b"password"
    assert guided.queries < uniform.queries


def test_query_budget_is_respected():
    oracle = f.FakeNoisyOracle(seed=5)
    got = posterior_attack(oracle, two_blocks(PREFIX + b"password"), 8,
                           max_queries=50)
    assert len(got) == 8
    assert oracle.queries <= 50


def test_timing_llr_sign():
    mid = (MU_R + MU_W) / 2
    assert timing_llr(mid) == pytest.approx(0.0)
    assert timing_llr(MU_R) > 0
    assert timing_llr(MU_W) < 0
    assert timing_llr(MU_R) == pytest.approx(-timing_llr(MU_W))


def test_bad_inputs_are_rejected():
    ct = two_blocks(PREFIX + b"password")
    oracle = f.FakeNoisyOracle(seed=6)
    with pytest.raises(ValueError):          # a zero makes a byte unreachable
        posterior_attack(oracle, ct, 8, prior=lambda s: [0.0] + [1 / 255] * 255)
    with pytest.raises(ValueError):          # not 256 values
        posterior_attack(oracle, ct, 8, prior=lambda s: [1 / 255] * 255)
    with pytest.raises(ValueError):          # three blocks
        posterior_attack(oracle, ct + bytes(16), 8)


def test_extra_params_are_accepted():
    # The harness passes settings such as k; the attack must not crash on them.
    oracle = f.FakeNoisyOracle(seed=7)
    got = posterior_attack(oracle, two_blocks(PREFIX + b"password"), 8,
                           max_queries=10, k=0.1)
    assert len(got) == 8
