"""T8b: the three D14 pattern checks for Tier 2.

Tier 2 has no number threshold like Tier 1's "±5% of 128" — it is checked by
pattern: dictionary beats random block, the sequential test beats a fixed-
sample one, and noise off matches Tier 1. The "fixed-sample" baseline is just
T7's sequential_attack with tau pushed to +-infinity: no early stop, decide
on the final sign after a set number of samples.
"""

from __future__ import annotations

import argparse
import csv
import math
import random
import statistics
from pathlib import Path
from statistics import NormalDist

from padding_oracle.core.contracts import CSV_COLUMNS
from padding_oracle.core.fakes import FakePerfectOracle, toy_block_encrypt
from padding_oracle.tier1.attack import attack as vaudenay_attack
from padding_oracle.tier2 import (
    MU_R, MU_W, SIGMA, GaussianTimingOracle, sequential_attack, wald_thresholds,
)
from padding_oracle.tier2.dictionary_attack import load_words, make_candidate_order

PREFIX = b"filler12"   # known 8-byte prefix, layout D15
N_TRIALS = 30           # trials per check — our own choice, not from a source
EPSILON = 0.01          # false-accept/false-reject rate for T7's test — our own choice


def _block_ciphertext(plain16: bytes, iv: bytes = bytes(16)) -> bytes:
    """IV + one target block whose decrypted plaintext is exactly `plain16`."""
    block = toy_block_encrypt(bytes(p ^ i for p, i in zip(plain16, iv)))
    return iv + block


def _row(experiment, attack, oracle, seed, target, band, n_bytes, queries, success, params):
    return {"experiment": experiment, "attack": attack, "oracle": type(oracle).__name__,
            "seed": seed, "target": target, "band": band, "bytes_attacked": n_bytes,
            "queries": queries, "success": success, "params": params}


def check1_dictionary_vs_random_block(words, rng, tau_lo, tau_hi):
    """D14 (1): dictionary attack needs clearly fewer sessions than a random block."""
    order_fn = make_candidate_order(words)
    dict_rows, random_rows = [], []

    for i, word in enumerate(rng.sample(words, N_TRIALS), start=1):
        target = word.encode("ascii")
        ct = _block_ciphertext(PREFIX + target)
        oracle = GaussianTimingOracle(FakePerfectOracle(), seed=rng.getrandbits(32))
        rec = sequential_attack(oracle, ct, 8, tau_lo=tau_lo, tau_hi=tau_hi, candidate_order=order_fn)
        dict_rows.append(_row("tier2_dict_vs_random", "dictionary", oracle, i, f"word_{i:03d}", "",
                               8, oracle.queries, int(rec == target),
                               f"tau_lo={tau_lo:.3f};tau_hi={tau_hi:.3f}"))

    for i in range(1, N_TRIALS + 1):
        secret = bytes(rng.getrandbits(8) for _ in range(8))
        ct = _block_ciphertext(PREFIX + secret)
        oracle = GaussianTimingOracle(FakePerfectOracle(), seed=rng.getrandbits(32))
        rec = sequential_attack(oracle, ct, 8, tau_lo=tau_lo, tau_hi=tau_hi, candidate_order=None)
        random_rows.append(_row("tier2_dict_vs_random", "random_block", oracle, i, f"random_block_{i:03d}",
                                 "", 8, oracle.queries, int(rec == secret),
                                 f"tau_lo={tau_lo:.3f};tau_hi={tau_hi:.3f}"))
    return dict_rows, random_rows


def check2_sequential_vs_fixed(words, rng, tau_lo, tau_hi, n_fixed):
    """D14 (2): the sequential test needs fewer queries than the fixed-sample
    method (Canvel's DecryptBlock2) — same candidate list, just no early stop."""
    order_fn = make_candidate_order(words)
    rows, seq_q, fixed_q = [], [], []

    for i, word in enumerate(rng.sample(words, N_TRIALS), start=1):
        target = word.encode("ascii")
        ct = _block_ciphertext(PREFIX + target)

        o1 = GaussianTimingOracle(FakePerfectOracle(), seed=rng.getrandbits(32))
        rec1 = sequential_attack(o1, ct, 8, tau_lo=tau_lo, tau_hi=tau_hi, candidate_order=order_fn)
        seq_q.append(o1.queries)
        rows.append(_row("tier2_sequential_vs_fixed", "sequential", o1, i, f"word_{i:03d}", "",
                          8, o1.queries, int(rec1 == target), f"tau_lo={tau_lo:.3f};tau_hi={tau_hi:.3f}"))

        o2 = GaussianTimingOracle(FakePerfectOracle(), seed=rng.getrandbits(32))
        rec2 = sequential_attack(o2, ct, 8, tau_lo=-math.inf, tau_hi=math.inf,
                                  max_samples=n_fixed, candidate_order=order_fn)
        fixed_q.append(o2.queries)
        rows.append(_row("tier2_sequential_vs_fixed", "fixed_sample", o2, i, f"word_{i:03d}", "",
                          8, o2.queries, int(rec2 == target), f"n_fixed={n_fixed}"))

    ratio = statistics.mean(fixed_q) / statistics.mean(seq_q)
    wrong_fixed = sum(1 for row in rows if row["attack"] == "fixed_sample" and not row["success"])
    return rows, ratio, wrong_fixed


def check3_noise_off_matches_tier1(rng, tau_lo, tau_hi):
    """D14 (3): with noise off, Tier 2 recovers the same plaintext as Tier 1."""
    secret = bytes(rng.getrandbits(8) for _ in range(8))
    ct = _block_ciphertext(PREFIX + secret)

    o1 = FakePerfectOracle()
    tier1_bytes = vaudenay_attack(o1, ct, 8)

    o2 = GaussianTimingOracle(FakePerfectOracle(), noise=False)
    tier2_bytes = sequential_attack(o2, ct, 8, tau_lo=tau_lo, tau_hi=tau_hi, candidate_order=None)

    rows = [
        _row("tier2_noise_off", "vaudenay", o1, "-", "noise_off_block", "", 8,
             o1.queries, int(tier1_bytes == secret), ""),
        _row("tier2_noise_off", "sequential_noise_off", o2, "-", "noise_off_block", "", 8,
             o2.queries, int(tier2_bytes == secret), f"tau_lo={tau_lo:.3f};tau_hi={tau_hi:.3f}"),
    ]
    return rows, tier1_bytes == tier2_bytes


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20261112)
    parser.add_argument("--output", type=Path, default=Path("results/tier2_pattern_checks.csv"))
    args = parser.parse_args()

    rng = random.Random(args.seed)
    words = load_words()
    tau_lo, tau_hi = wald_thresholds(EPSILON, EPSILON)
    # Fixed-sample size calibrated for two-sided error rate EPSILON (equal-variance Gaussian test)
    z = NormalDist().inv_cdf(1.0 - EPSILON)                         
    n_fixed = math.ceil((2 * z * SIGMA / (MU_R - MU_W)) ** 2)

    dict_rows, random_rows = check1_dictionary_vs_random_block(words, rng, tau_lo, tau_hi)
    seq_rows, ratio, wrong_fixed = check2_sequential_vs_fixed(words, rng, tau_lo, tau_hi, n_fixed)
    noise_rows, same_plaintext = check3_noise_off_matches_tier1(rng, tau_lo, tau_hi)
    rows = dict_rows + random_rows + seq_rows + noise_rows

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    dict_mean = statistics.mean(r["queries"] for r in dict_rows)
    random_mean = statistics.mean(r["queries"] for r in random_rows)

    print(f"CSV: {args.output}")
    print(f"(1) dictionary avg = {dict_mean:.1f}, random block avg = {random_mean:.1f} "
          f"-> fewer sessions: {dict_mean < random_mean}")
    print(f"(2) fixed/sequential query ratio = {ratio:.2f}x (Canvel: 4-5x, by pattern only); "
          f"fixed_sample wrong on {wrong_fixed}/{N_TRIALS} words")
    print(f"(3) noise-off Tier2 == Tier1 plaintext: {same_plaintext}")


if __name__ == "__main__":
    main()