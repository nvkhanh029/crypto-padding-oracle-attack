"""Smoke tests for T7: the Canvel-style sequential test."""

import math
import random

import pytest

from padding_oracle.core import contracts as c
from padding_oracle.core import fakes as f
from padding_oracle.tier2 import (
    MU_R,
    MU_W,
    SIGMA,
    GaussianTimingOracle,
    canvel_thresholds,
    dictionary_c0,
    random_block_c0,
    sequential_attack,
    sequential_check,
    wald_thresholds,
)


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


def _llr_step(sample, mu_r=MU_R, mu_w=MU_W, sigma=SIGMA):
    return (mu_r - mu_w) * (sample - (mu_r + mu_w) / 2.0) / (sigma * sigma)


def _samples_to_cross(threshold, step):
    """How many identical samples the test needs to reach `threshold`."""
    log_lr = 0.0
    n = 0
    while log_lr < threshold:
        log_lr += step
        n += 1
    return n


def test_wald_thresholds_are_log_odds():
    tau_lo, tau_hi = wald_thresholds(0.01, 0.02)
    assert tau_lo == pytest.approx(math.log(0.02 / 0.99))
    assert tau_hi == pytest.approx(math.log(0.98 / 0.01))
    assert tau_lo < 0.0 < tau_hi

    for bad in [(0.0, 0.1), (1.0, 0.1), (0.1, 0.0), (0.1, 1.0), (0.6, 0.6)]:
        with pytest.raises(ValueError):
            wald_thresholds(*bad)


def test_canvel_thresholds_match_canvel_table_1():
    # Canvel Table 1: C0 = 31, b = 8, p = 0.5 gives log tau- ~ -2.74,
    # log tau+ ~ 4.86 (values checked in docs/canvel-fact-check.md).
    tau_lo, tau_hi = canvel_thresholds(31, 8, 0.5)
    assert tau_lo == pytest.approx(-2.74, abs=0.01)
    assert tau_hi == pytest.approx(4.86, abs=0.01)
    assert tau_lo < 0.0 < tau_hi

    for bad in [(8, 8, 0.5), (31, 8, 0.0), (31, 8, 1.0)]:
        with pytest.raises(ValueError):
            canvel_thresholds(*bad)


def test_random_block_c0():
    assert random_block_c0(8) == 1028


def test_dictionary_c0_counts_candidates_tried():
    # One word and one candidate per byte: C0 is the sum over 8 bytes.
    assert dictionary_c0(["password"]) == pytest.approx(8.0)


def test_noise_off_decides_the_padding_correctly():
    o = GaussianTimingOracle(f.FakePerfectOracle(), noise=False)
    args = {"tau_lo": -2.0, "tau_hi": 2.0}
    assert sequential_check(o, _valid_ct(), **args) is True
    assert sequential_check(o, _invalid_ct(), **args) is False


def test_check_counts_exactly_the_samples_it_draws():
    o = GaussianTimingOracle(f.FakePerfectOracle(), noise=False)
    tau_lo, tau_hi = -2.5, 2.5
    expected = _samples_to_cross(tau_hi, _llr_step(MU_R))

    assert sequential_check(o, _valid_ct(), tau_lo=tau_lo, tau_hi=tau_hi) is True
    assert o.queries == expected


def test_max_samples_caps_the_number_of_queries():
    o = GaussianTimingOracle(f.FakePerfectOracle(), noise=False)
    args = {"tau_lo": -1000.0, "tau_hi": 1000.0, "max_samples": 1}

    assert sequential_check(o, _valid_ct(), **args) is True
    assert o.queries == 1
    assert sequential_check(o, _invalid_ct(), **args) is False
    assert o.queries == 2


def test_noise_on_keeps_the_error_rates_low():
    o = GaussianTimingOracle(f.FakePerfectOracle(), seed=11)
    tau_lo, tau_hi = wald_thresholds(0.01, 0.01)
    good, bad = _valid_ct(), _invalid_ct()
    trials = 60

    false_rejects = sum(
        not sequential_check(o, good, tau_lo=tau_lo, tau_hi=tau_hi)
        for _ in range(trials)
    )
    false_accepts = sum(
        sequential_check(o, bad, tau_lo=tau_lo, tau_hi=tau_hi)
        for _ in range(trials)
    )
    assert false_rejects <= 6
    assert false_accepts <= 6


def test_check_rejects_bad_inputs_without_counting():
    o = GaussianTimingOracle(f.FakePerfectOracle(), noise=False)
    args = {"tau_lo": -2.0, "tau_hi": 2.0}

    with pytest.raises(ValueError):
        sequential_check(o, b"short", **args)
    with pytest.raises(ValueError):
        sequential_check(o, b"x" * 48, **args)     # three blocks
    assert o.queries == 0

    ct = _valid_ct()
    with pytest.raises(ValueError):
        sequential_check(o, ct, tau_lo=0.0, tau_hi=2.0)
    with pytest.raises(ValueError):
        sequential_check(o, ct, tau_lo=-2.0, tau_hi=2.0, mu_r=MU_W)
    with pytest.raises(ValueError):
        sequential_check(o, ct, tau_lo=-2.0, tau_hi=2.0, sigma=0.0)
    with pytest.raises(ValueError):
        sequential_check(o, ct, tau_lo=-2.0, tau_hi=2.0, max_samples=0)


def test_attack_recovers_the_d15_word_with_noise_off():
    plain = b"prefix12" + b"password"
    ct = f.fake_cbc_encrypt(plain, bytes(16))[:32]
    o = GaussianTimingOracle(f.FakePerfectOracle(), noise=False)

    recovered = sequential_attack(o, ct, 8, tau_lo=-3.0, tau_hi=3.0)
    assert recovered == b"password"
    assert len(recovered) == 8
    assert o.queries > 0


def test_attack_recovers_a_full_block_with_noise_off():
    plain = b"0123456789abcdef"
    ct = f.fake_cbc_encrypt(plain, bytes(16))[:32]
    o = GaussianTimingOracle(f.FakePerfectOracle(), noise=False)

    recovered = sequential_attack(o, ct, 16, tau_lo=-3.0, tau_hi=3.0)
    assert recovered == plain


def test_attack_rejects_last_byte_false_positive_with_noise_off():
    # A wrong guess of 0x02 at the last byte turns the real 02 02 plaintext
    # suffix into valid padding. The confirmation check must reject it.
    plain = b"0123456789abcd" + b"\x02C"
    ct = f.fake_cbc_encrypt(plain, bytes(16))[:32]
    o = GaussianTimingOracle(f.FakePerfectOracle(), noise=False)

    assert sequential_attack(o, ct, 16, tau_lo=-3.0, tau_hi=3.0) == plain


def test_random_blocks_have_no_last_byte_false_positive():
    # Two thousand full random blocks. One sample per candidate is enough with
    # the noise off (the sample sign already gives the decision); the last-byte
    # confirmation still has to reject the false 02 02 padding.
    rng = random.Random(20261114)
    o = GaussianTimingOracle(f.FakePerfectOracle(), noise=False)
    wrong = 0

    for _ in range(2000):
        plain = rng.randbytes(16)
        ct = f.fake_cbc_encrypt(plain, bytes(16))[:32]
        got = sequential_attack(
            o, ct, 16, tau_lo=-1e9, tau_hi=1e9, max_samples=1
        )
        if got != plain:
            wrong += 1

    assert wrong == 0


def test_attack_uses_the_candidate_order_right_to_left():
    word = b"password"
    plain = b"prefix12" + word
    ct = f.fake_cbc_encrypt(plain, bytes(16))[:32]
    o = GaussianTimingOracle(f.FakePerfectOracle(), noise=False)
    seen = []

    def candidate_order(position, suffix):
        seen.append((position, suffix))
        truth = plain[position]
        return [truth] + [v for v in range(256) if v != truth]

    recovered = sequential_attack(
        o, ct, 8, tau_lo=-2.0, tau_hi=2.0, candidate_order=candidate_order
    )
    assert recovered == word
    assert [position for position, _ in seen] == list(range(15, 7, -1))
    assert [len(suffix) for _, suffix in seen] == list(range(8))
    assert seen[0][1] == b""
    assert seen[-1][1] == word[1:]

    # The true candidate came first every time, so each byte needed only the
    # samples that cross tau_hi; position 15 also needs one confirmation.
    per_byte = _samples_to_cross(2.0, _llr_step(MU_R))
    assert o.queries == 9 * per_byte


def test_attack_falls_back_when_no_candidate_is_accepted():
    plain = b"prefix12" + b"password"
    ct = f.fake_cbc_encrypt(plain, bytes(16))[:32]
    o = GaussianTimingOracle(f.FakePerfectOracle(), noise=False)

    def wrong_only(position, suffix):
        return [(plain[position] + 1) % 256]

    # One byte only, so the retry count is not confused by a wrong suffix.
    recovered = sequential_attack(
        o, ct, 1, tau_lo=-2.0, tau_hi=2.0, candidate_order=wrong_only
    )
    assert len(recovered) == 1
    assert recovered != plain[-1:]

    # One rejected candidate per round; the list is retried 3 times.
    per_check = _samples_to_cross(2.0, _llr_step(MU_R))
    assert o.queries == 3 * per_check


def test_attack_rejects_bad_inputs():
    o = GaussianTimingOracle(f.FakePerfectOracle(), noise=False)
    ct = _valid_ct()
    args = {"tau_lo": -2.0, "tau_hi": 2.0}

    for n_bytes in (0, 17):
        with pytest.raises(ValueError):
            sequential_attack(o, ct, n_bytes, **args)
    with pytest.raises(ValueError):
        sequential_attack(o, b"x" * 48, 8, **args)
    with pytest.raises(TypeError):
        sequential_attack(o, ct, 8, candidate_order=42, **args)
    with pytest.raises(ValueError):
        sequential_attack(
            o, ct, 8, candidate_order=lambda position, suffix: [], **args
        )
    with pytest.raises(ValueError):
        sequential_attack(
            o, ct, 8, candidate_order=lambda position, suffix: [256], **args
        )


def test_functions_match_the_contract_shapes():
    assert isinstance(sequential_check, c.SequentialCheck)
    assert isinstance(sequential_attack, c.Attack)
