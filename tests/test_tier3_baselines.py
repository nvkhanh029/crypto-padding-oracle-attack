"""Smoke tests for T11: the NCC and Sequential Halving baselines."""

import pytest

from padding_oracle.core import contracts as c
from padding_oracle.core import fakes as f
from padding_oracle.tier2 import GaussianTimingOracle
from padding_oracle.tier3 import (
    ncc_attack,
    posterior_attack,
    sequential_halving_attack,
    uniform_prior,
)

PREFIX = b"prefix00"          # known 8-byte prefix (D15)
WORD = b"password"


def two_blocks(plain16: bytes) -> bytes:
    """IV + the target block for a 16-byte plaintext."""
    return f.fake_cbc_encrypt(plain16, bytes(16))[:32]


# --- Baseline (c): NCC = posterior-threshold with a uniform prior ----------

def test_ncc_matches_the_posterior_attack_with_a_uniform_prior():
    ct = two_blocks(PREFIX + WORD)
    ncc_oracle = f.FakeNoisyOracle(seed=1)
    posterior_oracle = f.FakeNoisyOracle(seed=1)

    got_ncc = ncc_attack(ncc_oracle, ct, 8, seed=1)
    got_posterior = posterior_attack(
        posterior_oracle, ct, 8, prior=uniform_prior, seed=1
    )

    assert got_ncc == got_posterior == WORD
    assert ncc_oracle.queries == posterior_oracle.queries


def test_ncc_respects_a_query_budget():
    oracle = f.FakeNoisyOracle(seed=2)
    got = ncc_attack(oracle, two_blocks(PREFIX + WORD), 8, max_queries=20)
    assert len(got) == 8
    assert oracle.queries <= 20


def test_ncc_accepts_extra_harness_params():
    oracle = f.FakeNoisyOracle(seed=3)
    got = ncc_attack(oracle, two_blocks(PREFIX + WORD), 8, k=0.1,
                     max_queries=10)
    assert len(got) == 8


def test_ncc_matches_the_attack_shape():
    assert isinstance(ncc_attack, c.Attack)


# --- Sequential Halving ----------------------------------------------------

def test_sequential_halving_recovers_the_word_with_noise_off():
    oracle = GaussianTimingOracle(f.FakePerfectOracle(), noise=False)
    ct = two_blocks(PREFIX + WORD)

    got = sequential_halving_attack(
        oracle, ct, 8, budget_per_byte=2048, seed=1
    )
    assert got == WORD
    assert oracle.queries == 8 * 2048       # each round spends the whole budget


def test_sequential_halving_recovers_a_full_block_with_noise_off():
    plain = b"0123456789abcdef"
    oracle = GaussianTimingOracle(f.FakePerfectOracle(), noise=False)

    got = sequential_halving_attack(
        oracle, two_blocks(plain), 16, budget_per_byte=2048, seed=2
    )
    assert got == plain


def test_sequential_halving_works_under_noise():
    oracle = f.FakeNoisyOracle(seed=5)
    got = sequential_halving_attack(
        oracle, two_blocks(PREFIX + WORD), 8, budget_per_byte=20000, seed=5
    )
    assert got == WORD


def test_sequential_halving_stays_inside_the_budget():
    oracle = GaussianTimingOracle(f.FakePerfectOracle(), noise=False)
    budget = 3000

    got = sequential_halving_attack(
        oracle, two_blocks(PREFIX + WORD), 8, budget_per_byte=budget, seed=3
    )
    assert len(got) == 8
    assert 0 < oracle.queries <= 8 * budget


def test_sequential_halving_accepts_extra_harness_params():
    oracle = GaussianTimingOracle(f.FakePerfectOracle(), noise=False)
    got = sequential_halving_attack(
        oracle, two_blocks(PREFIX + WORD), 8, budget_per_byte=2048,
        seed=4, k=0.1, delta=0.5,
    )
    assert len(got) == 8


def test_sequential_halving_rejects_a_budget_below_one_sample_per_round():
    oracle = GaussianTimingOracle(f.FakePerfectOracle(), noise=False)
    ct = two_blocks(PREFIX + WORD)

    for budget in (0, 2047):
        with pytest.raises(ValueError):
            sequential_halving_attack(
                oracle, ct, 8, budget_per_byte=budget
            )
    with pytest.raises(ValueError):
        sequential_halving_attack(
            oracle, ct, 8, budget_per_byte=2048.0
        )


def test_sequential_halving_rejects_bad_inputs():
    oracle = GaussianTimingOracle(f.FakePerfectOracle(), noise=False)
    ct = two_blocks(PREFIX + WORD)

    with pytest.raises(ValueError):
        sequential_halving_attack(
            oracle, ct + bytes(16), 8, budget_per_byte=2048
        )
    for n_bytes in (0, 17):
        with pytest.raises(ValueError):
            sequential_halving_attack(
                oracle, ct, n_bytes, budget_per_byte=2048
            )


def test_sequential_halving_matches_the_attack_shape():
    assert isinstance(sequential_halving_attack, c.Attack)
