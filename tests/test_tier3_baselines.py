"""Smoke tests for T11: the NCC and Sequential Halving baselines."""

import random

import pytest

from padding_oracle.core import contracts as c
from padding_oracle.core import fakes as f
from padding_oracle.core.contracts import NoisyOracle
from padding_oracle.tier2 import GaussianTimingOracle
from padding_oracle.tier3 import (
    ncc_attack,
    posterior_attack,
    sequential_halving_attack,
    uniform_prior,
)
from padding_oracle.tier3.baselines import (
    N_CANDIDATES,
    SH_ROUNDS,
    sequential_halving_byte,
)

PREFIX = b"prefix00"          # known 8-byte prefix (D15)
WORD = b"password"


def two_blocks(plain16: bytes) -> bytes:
    """IV + the target block for a 16-byte plaintext."""
    return f.fake_cbc_encrypt(plain16, bytes(16))[:32]


def _sh_queries_per_byte(budget: int) -> int:
    """New queries used by one Sequential Halving byte run (round floors)."""
    remaining = N_CANDIDATES
    total = 0
    for _ in range(SH_ROUNDS):
        total += (budget // (remaining * SH_ROUNDS)) * remaining
        remaining = max(1, remaining // 2)
    return total


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


def test_ncc_ignores_a_prior_passed_in_params():
    ct = two_blocks(PREFIX + WORD)
    baseline_oracle = f.FakeNoisyOracle(seed=8)
    baseline = ncc_attack(baseline_oracle, ct, 8, seed=8)

    other_oracle = f.FakeNoisyOracle(seed=8)
    got = ncc_attack(
        other_oracle, ct, 8, seed=8,
        prior=lambda suffix: [1.0 / 256] * 256,
    )

    assert got == baseline                 # NCC keeps its uniform prior
    assert other_oracle.queries == baseline_oracle.queries


def test_ncc_matches_the_attack_shape():
    assert isinstance(ncc_attack, c.Attack)


# --- Sequential Halving ----------------------------------------------------

def test_sequential_halving_recovers_the_word_with_noise_off():
    oracle = GaussianTimingOracle(f.FakePerfectOracle(), noise=False)
    ct = two_blocks(PREFIX + WORD)

    got = sequential_halving_attack(
        oracle, ct, 8, max_queries=8 * 2048, seed=1
    )
    assert got == WORD
    assert oracle.queries == 8 * 2048       # 8 rounds x 256 queries per byte


def test_sequential_halving_recovers_a_full_block_with_noise_off():
    plain = b"0123456789abcdef"
    oracle = GaussianTimingOracle(f.FakePerfectOracle(), noise=False)

    got = sequential_halving_attack(
        oracle, two_blocks(plain), 16, max_queries=16 * 2048, seed=2
    )
    assert got == plain


def test_sequential_halving_works_under_noise():
    oracle = f.FakeNoisyOracle(seed=5)
    got = sequential_halving_attack(
        oracle, two_blocks(PREFIX + WORD), 8, max_queries=8 * 20000, seed=5
    )
    assert got == WORD


def test_sequential_halving_stays_inside_the_budget():
    oracle = GaussianTimingOracle(f.FakePerfectOracle(), noise=False)
    budget_per_byte = 3000
    max_queries = 8 * budget_per_byte

    got = sequential_halving_attack(
        oracle, two_blocks(PREFIX + WORD), 8, max_queries=max_queries, seed=3
    )
    assert len(got) == 8
    assert 0 < oracle.queries <= max_queries


def test_sequential_halving_leaves_unused_budget_after_flooring():
    oracle = GaussianTimingOracle(f.FakePerfectOracle(), noise=False)
    budget_per_byte = 3000
    max_queries = 8 * budget_per_byte

    sequential_halving_attack(
        oracle, two_blocks(PREFIX + WORD), 8, max_queries=max_queries, seed=3
    )
    assert oracle.queries == 8 * _sh_queries_per_byte(budget_per_byte)
    assert oracle.queries < max_queries


class _ScriptedOracle(NoisyOracle):
    """Return scripted timings for two candidates, round by round."""

    def __init__(self, prev: bytes, position: int, pad: int,
                 candidate_a: int, candidate_b: int) -> None:
        super().__init__()
        self.prev = prev
        self.position = position
        self.pad = pad
        self.candidate_a = candidate_a
        self.candidate_b = candidate_b
        self.calls: dict[int, int] = {}

    def _answer(self, ciphertext: bytes) -> float:
        guess = (
            ciphertext[self.position] ^ self.prev[self.position] ^ self.pad
        )
        index = self.calls.get(guess, 0)
        self.calls[guess] = index + 1

        if guess == self.candidate_a:
            return 1000.0 if index == 0 else 0.0
        if guess == self.candidate_b:
            if index == 0:
                return 1.0
            # Round 8 starts after 1+2+4+8+16+32+64 = 127 calls.
            return 2.0 if index >= 127 else 0.0
        return 0.0


def test_sequential_halving_counts_only_the_current_round_samples():
    # Round 1: A=1000, B=1, so both survive. Round 8: A=0, B=2.
    # Per-round means pick B; cumulative means would pick A.
    candidate_a, candidate_b = 65, 66
    oracle = _ScriptedOracle(
        bytes(16), 15, 1, candidate_a, candidate_b
    )
    got = sequential_halving_byte(
        oracle, bytes(16), bytes(16), 15, {}, 2048, random.Random(0)
    )
    assert got == candidate_b


def test_sequential_halving_accepts_extra_harness_params():
    oracle = GaussianTimingOracle(f.FakePerfectOracle(), noise=False)
    got = sequential_halving_attack(
        oracle, two_blocks(PREFIX + WORD), 8, max_queries=8 * 2048,
        seed=4, k=0.1, delta=0.5,
    )
    assert len(got) == 8


def test_sequential_halving_requires_max_queries_not_budget_per_byte():
    oracle = GaussianTimingOracle(f.FakePerfectOracle(), noise=False)
    with pytest.raises(TypeError):
        sequential_halving_attack(
            oracle, two_blocks(PREFIX + WORD), 8, budget_per_byte=8 * 2048
        )


def test_sequential_halving_rejects_a_budget_below_one_sample_per_round():
    oracle = GaussianTimingOracle(f.FakePerfectOracle(), noise=False)
    ct = two_blocks(PREFIX + WORD)

    for max_queries in (0, 8 * 2048 - 1):
        with pytest.raises(ValueError):
            sequential_halving_attack(
                oracle, ct, 8, max_queries=max_queries
            )
    with pytest.raises(ValueError):
        sequential_halving_attack(
            oracle, ct, 8, max_queries=8 * 2048.0
        )
    # A 16-byte block needs twice the minimum.
    with pytest.raises(ValueError):
        sequential_halving_attack(
            oracle, ct, 16, max_queries=16 * 2048 - 1
        )


def test_sequential_halving_rejects_bad_inputs():
    oracle = GaussianTimingOracle(f.FakePerfectOracle(), noise=False)
    ct = two_blocks(PREFIX + WORD)

    with pytest.raises(ValueError):
        sequential_halving_attack(
            oracle, ct + bytes(16), 8, max_queries=8 * 2048
        )
    for n_bytes in (0, 17):
        with pytest.raises(ValueError):
            sequential_halving_attack(
                oracle, ct, n_bytes, max_queries=8 * 2048
            )


def test_sequential_halving_matches_the_attack_shape():
    assert isinstance(sequential_halving_attack, c.Attack)
