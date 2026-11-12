"""Smoke tests for T6: the Gaussian timing oracle."""

import random
import statistics

import pytest

from padding_oracle.core import fakes as f
from padding_oracle.tier2 import MU_R, MU_W, SIGMA, GaussianTimingOracle


def _valid_ct():
    """IV + one block whose padding is valid."""
    return f.fake_cbc_encrypt(b"hello world", bytes(16))


def _invalid_ct():
    """Same ciphertext, last byte changed until the padding is invalid."""
    ct = bytearray(_valid_ct())
    for guess in range(256):
        ct[-1] = guess
        if not f.FakePerfectOracle().query(bytes(ct)):
            return bytes(ct)
    raise AssertionError("no invalid padding found")


def test_query_returns_float_and_counts_exactly_once():
    inner = f.FakePerfectOracle()
    o = GaussianTimingOracle(inner, seed=1)
    ct = _valid_ct()

    sample = o.query(ct)
    assert isinstance(sample, float)
    assert not isinstance(sample, bool)      # never the true yes/no
    assert o.queries == 1
    assert inner.queries == 0                # inner check is not counted

    o.query(ct)
    assert o.queries == 2
    o.reset()
    assert o.queries == 0


def test_rejected_ciphertext_is_not_counted():
    o = GaussianTimingOracle(f.FakePerfectOracle(), seed=1)
    with pytest.raises(ValueError):
        o.query(b"short")
    assert o.queries == 0


def test_means_follow_the_truth():
    o = GaussianTimingOracle(f.FakePerfectOracle(), seed=2)
    good, bad = _valid_ct(), _invalid_ct()
    n = 2000

    mean_good = sum(o.query(good) for _ in range(n)) / n
    mean_bad = sum(o.query(bad) for _ in range(n)) / n

    assert abs(mean_good - MU_R) < 0.3
    assert abs(mean_bad - MU_W) < 0.3


def test_noise_has_the_configured_spread():
    o = GaussianTimingOracle(f.FakePerfectOracle(), seed=3)
    good = _valid_ct()
    samples = [o.query(good) for _ in range(4000)]
    assert abs(statistics.stdev(samples) - SIGMA) < 0.15


def test_custom_timing_parameters_are_inputs():
    o = GaussianTimingOracle(
        f.FakePerfectOracle(), seed=4, mu_r=100.0, mu_w=50.0, sigma=2.0
    )
    n = 2000
    mean_good = sum(o.query(_valid_ct()) for _ in range(n)) / n
    mean_bad = sum(o.query(_invalid_ct()) for _ in range(n)) / n
    assert abs(mean_good - 100.0) < 0.3
    assert abs(mean_bad - 50.0) < 0.3


def test_same_seed_repeats_the_samples():
    ct = _valid_ct()
    a = GaussianTimingOracle(f.FakePerfectOracle(), seed=42)
    b = GaussianTimingOracle(f.FakePerfectOracle(), seed=42)
    c = GaussianTimingOracle(f.FakePerfectOracle(), seed=43)

    seq_a = [a.query(ct) for _ in range(8)]
    seq_b = [b.query(ct) for _ in range(8)]
    seq_c = [c.query(ct) for _ in range(8)]
    assert seq_a == seq_b
    assert seq_a != seq_c


def test_noise_off_returns_the_exact_means():
    o = GaussianTimingOracle(f.FakePerfectOracle(), seed=5, noise=False)
    good, bad = _valid_ct(), _invalid_ct()

    assert o.query(good) == MU_R
    assert o.query(bad) == MU_W
    assert o.query(good) == MU_R          # deterministic, no random part
    assert o.queries == 3


def test_noise_off_classifies_every_sample_correctly():
    o = GaussianTimingOracle(f.FakePerfectOracle(), noise=False)
    mid = (MU_R + MU_W) / 2

    assert o.query(_valid_ct()) > mid
    assert o.query(_invalid_ct()) < mid


def test_noise_can_be_switched_off_after_construction():
    o = GaussianTimingOracle(f.FakePerfectOracle(), seed=6)
    assert o.noise is True
    o.noise = False
    assert o.query(_valid_ct()) == MU_R


def test_invalid_timing_parameters_are_rejected():
    with pytest.raises(ValueError):
        GaussianTimingOracle(f.FakePerfectOracle(), sigma=-1.0)
    with pytest.raises(TypeError):
        GaussianTimingOracle("not an oracle")  # type: ignore[arg-type]


def test_rng_is_a_seeded_local_instance():
    # The oracle must not touch the global random state (AGENTS.md rule).
    random.seed(123)
    before = random.random()
    random.seed(123)
    GaussianTimingOracle(f.FakePerfectOracle(), seed=7).query(_valid_ct())
    after = random.random()
    assert before == after
