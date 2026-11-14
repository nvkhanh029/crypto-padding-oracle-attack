from padding_oracle.core import fakes as f
from padding_oracle.tier2 import GaussianTimingOracle, wald_thresholds
from padding_oracle.tier2.dictionary_attack import dictionary_attack, make_candidate_order

WORDS = ["mountain", "password", "sandwich"]  # fake dictionary, small, for quick testing


def _ct_for(prefix: bytes, word: str) -> bytes:
    """IV + 1 target block, plaintext = prefix(8) + word(8), không cần qua padding."""
    plain = prefix + word.encode("ascii")
    iv = bytes(16)
    block = f.toy_block_encrypt(bytes(p ^ i for p, i in zip(plain, iv)))
    return iv + block


def test_candidate_order_narrows_down_to_one_word():
    order_fn = make_candidate_order(WORDS)
    first = order_fn(15, b"")                 # don't know anything -> the last 3 letters are different
    assert set(first) == {ord("n"), ord("d"), ord("h")}
    narrowed = order_fn(9, b"ssword")         # only "password" matches the suffix "ssword"
    assert narrowed == [ord("a")]


def test_dictionary_attack_recovers_the_word():
    ct = _ct_for(b"filler12", "password")
    oracle = GaussianTimingOracle(f.FakePerfectOracle(), noise=False, seed=0)
    tau_lo, tau_hi = wald_thresholds(0.01, 0.01)

    recovered = dictionary_attack(
        oracle, ct, 8, tau_lo=tau_lo, tau_hi=tau_hi, words=WORDS
    )
    assert recovered == b"password"