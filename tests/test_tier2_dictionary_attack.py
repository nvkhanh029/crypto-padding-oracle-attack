"""Smoke tests for the dictionary attack (T8a), on the fake oracle."""

import pytest

from padding_oracle.core import fakes as f
from padding_oracle.tier2 import GaussianTimingOracle, wald_thresholds
from padding_oracle.tier2.dictionary_attack import (
    dictionary_attack,
    load_words,
    make_candidate_order,
)

WORDS = ["mountain", "password", "sandwich"]  # small fake dictionary, for speed
PREFIX = b"filler12"                          # known 8-byte prefix (D15)


def _ct_for(prefix: bytes, word: str) -> bytes:
    """IV + one target block whose plaintext is prefix (8) + word (8)."""
    plain = prefix + word.encode("ascii")
    iv = bytes(16)
    block = f.toy_block_encrypt(bytes(p ^ i for p, i in zip(plain, iv)))
    return iv + block


def test_candidate_order_narrows_down_to_one_word():
    order_fn = make_candidate_order(WORDS)
    first = order_fn(15, b"")                 # nothing known: the three last letters
    assert set(first) == {ord("n"), ord("d"), ord("h")}
    narrowed = order_fn(9, b"ssword")         # only "password" ends with "ssword"
    assert narrowed == [ord("a")]


def test_candidate_order_follows_the_word_list_order():
    # "mountain" comes before "password" and "sandwich" in the list.
    order_fn = make_candidate_order(WORDS)
    assert order_fn(15, b"") == [ord("n"), ord("d"), ord("h")]


def test_candidate_order_outside_the_dictionary():
    order_fn = make_candidate_order(WORDS)
    # No word ends with "zz": fall back to the letters a-z.
    assert order_fn(13, b"zz") == [ord(c) for c in "abcdefghijklmnopqrstuvwxyz"]
    # Left of the word (8 letters already known): every byte value.
    assert order_fn(7, b"password") == list(range(256))


def test_words_must_have_eight_letters():
    with pytest.raises(ValueError):
        make_candidate_order(["short"])


def test_dictionary_attack_recovers_the_word_noise_off():
    ct = _ct_for(PREFIX, "password")
    oracle = GaussianTimingOracle(f.FakePerfectOracle(), noise=False, seed=0)
    tau_lo, tau_hi = wald_thresholds(0.01, 0.01)

    recovered = dictionary_attack(
        oracle, ct, 8, tau_lo=tau_lo, tau_hi=tau_hi, words=WORDS
    )
    assert recovered == b"password"


def test_dictionary_attack_recovers_the_word_with_noise():
    ct = _ct_for(PREFIX, "sandwich")
    oracle = GaussianTimingOracle(f.FakePerfectOracle(), seed=1)
    tau_lo, tau_hi = wald_thresholds(0.001, 0.001)

    recovered = dictionary_attack(
        oracle, ct, 8, tau_lo=tau_lo, tau_hi=tau_hi, words=WORDS
    )
    assert recovered == b"sandwich"
    assert oracle.queries > 8                 # more than one sample per byte


def test_full_block_recovers_prefix_and_word():
    # n_bytes = 16: the 8 prefix bytes are not letters of a word, so the
    # attack must fall back to all 256 values there.
    ct = _ct_for(PREFIX, "mountain")
    oracle = GaussianTimingOracle(f.FakePerfectOracle(), noise=False)
    tau_lo, tau_hi = wald_thresholds(0.01, 0.01)

    recovered = dictionary_attack(
        oracle, ct, 16, tau_lo=tau_lo, tau_hi=tau_hi, words=WORDS
    )
    assert recovered == PREFIX + b"mountain"


def test_extra_params_are_ignored_but_a_budget_is_refused():
    ct = _ct_for(PREFIX, "password")
    tau_lo, tau_hi = wald_thresholds(0.01, 0.01)

    oracle = GaussianTimingOracle(f.FakePerfectOracle(), noise=False)
    recovered = dictionary_attack(
        oracle, ct, 8, tau_lo=tau_lo, tau_hi=tau_hi, words=WORDS, seed=42
    )
    assert recovered == b"password"

    with pytest.raises(ValueError):           # no silent "budget"
        dictionary_attack(
            oracle, ct, 8, tau_lo=tau_lo, tau_hi=tau_hi, words=WORDS,
            max_queries=1000,
        )


def test_default_word_list_loads():
    words = load_words()
    assert len(words) == 36322                # D11
    assert all(len(word) == 8 for word in words[:100])
