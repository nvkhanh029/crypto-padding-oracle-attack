"""T8b: Tier 2 experiments and the three D14 pattern checks, on real AES-CBC.

Tier 2 has no number threshold like Tier 1's "within 5% of 128". It is checked
by pattern (D14):

  (1) the dictionary attack needs clearly fewer queries than the random block;
  (2) the sequential test needs fewer queries than a fixed-sample test;
  (3) with the noise turned off, Tier 2 recovers the same plaintext as Tier 1.

Every row also records `success`, because a query count means nothing if the
recovered bytes are wrong.

Thresholds
----------
Check (1) uses Canvel's thresholds, Eq. (6)-(7) (`canvel_thresholds`), for the
target success probability SUCCESS_TARGET. They depend on C0, the average
number of candidates tried per block: a random block tries many more wrong
candidates than a dictionary word, so it needs a much higher accept threshold.
One fixed pair of thresholds for both attacks does not work: with a 1% false
accept rate per candidate, a random byte (about 128 wrong candidates tried)
is almost always accepted wrongly.

Check (2) compares two tests designed for the SAME error rate EPSILON on both
sides: the sequential test with `wald_thresholds(EPSILON, EPSILON)`, and a
fixed-sample test that takes `fixed_sample_size(EPSILON)` samples for every
candidate and accepts when the evidence is positive. The fixed-sample test is
T7's `sequential_attack` with the thresholds at infinity (no early stop).

From the repository root:
    $env:PYTHONPATH = "src"
    python -m padding_oracle.tier2.tier2_pattern_checks --seed 20261112
"""

from __future__ import annotations

import argparse
import csv
import math
import random
import statistics
from pathlib import Path
from statistics import NormalDist

from padding_oracle.core.contracts import BLOCK_SIZE, CSV_COLUMNS
from padding_oracle.tier1.aes import aes_cbc_encrypt
from padding_oracle.tier1.attack import attack as vaudenay_attack
from padding_oracle.tier1.oracle import AESPerfectOracle
from padding_oracle.tier2.dictionary_attack import (
    DEFAULT_WORDLIST_PATH,
    make_candidate_order,
)
from padding_oracle.tier2.noisy_oracle import MU_R, MU_W, SIGMA, GaussianTimingOracle
from padding_oracle.tier2.sequential import (
    canvel_thresholds,
    dictionary_c0,
    random_block_c0,
    sequential_attack,
    wald_thresholds,
)

DEFAULT_SEED = 20261112
N_TRIALS = 100          # targets per attack: our own choice (as Tier 1's 100 blocks)
SUCCESS_TARGET = 0.5    # p in Canvel Eq. (6)-(7); 0.5 is the case of his 166 vs 4,239
EPSILON = 0.01          # error rate of both tests in check (2): our own choice
PREFIX = b"filler12"    # known 8-byte prefix (D15)
WORD_BYTES = 8
AES_KEY_SIZE = 16


def random_bytes(rng: random.Random, length: int) -> bytes:
    """Generate deterministic bytes using the supplied RNG."""
    return bytes(rng.getrandbits(8) for _ in range(length))


def read_words_with_bands(path: Path | str = DEFAULT_WORDLIST_PATH) -> list[tuple[str, str]]:
    """Read (word, band) for every row of the word-list CSV."""
    with open(path, encoding="utf-8", newline="") as source:
        return [(row["word"], row["band"]) for row in csv.DictReader(source)]


def fixed_sample_size(epsilon: float) -> int:
    """Samples a fixed-sample test needs for error rate `epsilon` on both sides.

    The mean of n samples has standard deviation sigma / sqrt(n). Deciding at
    the middle of the two means is wrong with probability epsilon when the
    middle is z standard deviations away, with z the (1 - epsilon) quantile of
    the standard normal: (mu_r - mu_w) / 2 = z * sigma / sqrt(n).
    """
    z = NormalDist().inv_cdf(1.0 - epsilon)
    return math.ceil((2.0 * z * SIGMA / (MU_R - MU_W)) ** 2)


def _challenge(plain16: bytes, key: bytes, rng: random.Random) -> bytes:
    """IV + the one ciphertext block that decrypts to `plain16`."""
    iv = random_bytes(rng, BLOCK_SIZE)
    return aes_cbc_encrypt(plain16, key, iv)[:2 * BLOCK_SIZE]


def _noisy_oracle(key: bytes, rng: random.Random, noise: bool = True) -> GaussianTimingOracle:
    """A fresh timing oracle on real AES-CBC, with its own noise seed."""
    return GaussianTimingOracle(AESPerfectOracle(key), seed=rng.getrandbits(32), noise=noise)


def _row(experiment: str, attack: str, oracle, seed: int, target: str, band: str,
         n_bytes: int, success: bool, params: str) -> dict[str, object]:
    return {
        "experiment": experiment,
        "attack": attack,
        "oracle": type(oracle).__name__,
        "seed": seed,
        "target": target,
        "band": band,
        "bytes_attacked": n_bytes,
        "queries": oracle.queries,
        "success": int(success),
        "params": params,
    }


def _threshold_text(tau_lo: float, tau_hi: float) -> str:
    return f"tau_lo={tau_lo:.3f};tau_hi={tau_hi:.3f}"


def check1_dictionary_vs_random_block(words_with_bands, order_fn, c0_dictionary,
                                      key, rng, seed, n_trials):
    """D14 (1): the dictionary attack against the random-block baseline."""
    experiment = "tier2_dict_vs_random"
    rows = []

    tau_lo, tau_hi = canvel_thresholds(c0_dictionary, WORD_BYTES, SUCCESS_TARGET)
    params = (f"{_threshold_text(tau_lo, tau_hi)};p={SUCCESS_TARGET};"
              f"c0={c0_dictionary:.2f};inner=AESPerfectOracle")
    for word, band in rng.sample(words_with_bands, n_trials):
        target = word.encode("ascii")
        oracle = _noisy_oracle(key, rng)
        recovered = sequential_attack(
            oracle, _challenge(PREFIX + target, key, rng), WORD_BYTES,
            tau_lo=tau_lo, tau_hi=tau_hi, candidate_order=order_fn)
        rows.append(_row(experiment, "dictionary", oracle, seed, word, band,
                         WORD_BYTES, recovered == target, params))

    c0_random = random_block_c0(WORD_BYTES)
    tau_lo, tau_hi = canvel_thresholds(c0_random, WORD_BYTES, SUCCESS_TARGET)
    params = (f"{_threshold_text(tau_lo, tau_hi)};p={SUCCESS_TARGET};"
              f"c0={c0_random:.2f};inner=AESPerfectOracle")
    for number in range(1, n_trials + 1):
        target = random_bytes(rng, WORD_BYTES)
        oracle = _noisy_oracle(key, rng)
        recovered = sequential_attack(
            oracle, _challenge(PREFIX + target, key, rng), WORD_BYTES,
            tau_lo=tau_lo, tau_hi=tau_hi, candidate_order=None)
        rows.append(_row(experiment, "random_block", oracle, seed,
                         f"random_block_{number:03d}", "", WORD_BYTES,
                         recovered == target, params))
    return rows


def check2_sequential_vs_fixed(words_with_bands, order_fn, key, rng, seed, n_trials):
    """D14 (2): the sequential test against a fixed-sample test, same error rate."""
    experiment = "tier2_sequential_vs_fixed"
    tau_lo, tau_hi = wald_thresholds(EPSILON, EPSILON)
    n_fixed = fixed_sample_size(EPSILON)
    sequential_params = (f"{_threshold_text(tau_lo, tau_hi)};epsilon={EPSILON};"
                         "inner=AESPerfectOracle")
    fixed_params = f"n_fixed={n_fixed};epsilon={EPSILON};inner=AESPerfectOracle"
    rows = []

    for word, band in rng.sample(words_with_bands, n_trials):
        target = word.encode("ascii")
        challenge = _challenge(PREFIX + target, key, rng)

        oracle = _noisy_oracle(key, rng)
        recovered = sequential_attack(
            oracle, challenge, WORD_BYTES,
            tau_lo=tau_lo, tau_hi=tau_hi, candidate_order=order_fn)
        rows.append(_row(experiment, "sequential", oracle, seed, word, band,
                         WORD_BYTES, recovered == target, sequential_params))

        # Thresholds at infinity: no early stop. Every candidate gets exactly
        # n_fixed samples and is accepted when its evidence is positive.
        oracle = _noisy_oracle(key, rng)
        recovered = sequential_attack(
            oracle, challenge, WORD_BYTES,
            tau_lo=-math.inf, tau_hi=math.inf, max_samples=n_fixed,
            candidate_order=order_fn)
        rows.append(_row(experiment, "fixed_sample", oracle, seed, word, band,
                         WORD_BYTES, recovered == target, fixed_params))
    return rows


def check3_noise_off_matches_tier1(key, rng, seed, n_trials):
    """D14 (3): noise off, Tier 2 and Tier 1 recover the same full block."""
    experiment = "tier2_noise_off"
    tau_lo, tau_hi = canvel_thresholds(
        random_block_c0(BLOCK_SIZE), BLOCK_SIZE, SUCCESS_TARGET)
    params = f"{_threshold_text(tau_lo, tau_hi)};noise=off;inner=AESPerfectOracle"
    rows = []
    same_plaintext = 0

    for number in range(1, n_trials + 1):
        plaintext = random_bytes(rng, BLOCK_SIZE)
        challenge = _challenge(plaintext, key, rng)
        target = f"random_block_{number:03d}"

        perfect = AESPerfectOracle(key)
        tier1_bytes = vaudenay_attack(perfect, challenge, BLOCK_SIZE)
        rows.append(_row(experiment, "vaudenay", perfect, seed, target, "",
                         BLOCK_SIZE, tier1_bytes == plaintext, ""))

        noise_off = _noisy_oracle(key, rng, noise=False)
        tier2_bytes = sequential_attack(
            noise_off, challenge, BLOCK_SIZE,
            tau_lo=tau_lo, tau_hi=tau_hi, candidate_order=None)
        rows.append(_row(experiment, "sequential_noise_off", noise_off, seed,
                         target, "", BLOCK_SIZE, tier2_bytes == plaintext, params))

        same_plaintext += int(tier1_bytes == tier2_bytes == plaintext)
    return rows, same_plaintext


def _measured(rows: list[dict[str, object]], attack: str) -> tuple[float, int]:
    """Mean queries and number of successes for one attack's rows."""
    chosen = [row for row in rows if row["attack"] == attack]
    mean_queries = statistics.mean(int(row["queries"]) for row in chosen)
    successes = sum(int(row["success"]) for row in chosen)
    return mean_queries, successes


def run_checks(seed: int, output_path: Path, n_trials: int = N_TRIALS,
               words_with_bands: list[tuple[str, str]] | None = None) -> dict[str, object]:
    """Run the three checks, write the CSV rows, return the measured summary."""
    if words_with_bands is None:
        words_with_bands = read_words_with_bands()
    words = [word for word, _band in words_with_bands]
    order_fn = make_candidate_order(words)
    c0_dictionary = dictionary_c0(words)

    rng = random.Random(seed)
    # One deterministic AES key for all targets, as in the Tier 1 experiment.
    key = random_bytes(rng, AES_KEY_SIZE)

    rows1 = check1_dictionary_vs_random_block(
        words_with_bands, order_fn, c0_dictionary, key, rng, seed, n_trials)
    rows2 = check2_sequential_vs_fixed(
        words_with_bands, order_fn, key, rng, seed, n_trials)
    rows3, same_plaintext = check3_noise_off_matches_tier1(key, rng, seed, n_trials)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows1 + rows2 + rows3)

    dictionary_mean, dictionary_ok = _measured(rows1, "dictionary")
    random_mean, random_ok = _measured(rows1, "random_block")
    sequential_mean, sequential_ok = _measured(rows2, "sequential")
    fixed_mean, fixed_ok = _measured(rows2, "fixed_sample")
    return {
        "seed": seed,
        "n_trials": n_trials,
        "c0_dictionary": c0_dictionary,
        "c0_random_block": random_block_c0(WORD_BYTES),
        "dictionary_mean_queries": dictionary_mean,
        "dictionary_successes": dictionary_ok,
        "random_block_mean_queries": random_mean,
        "random_block_successes": random_ok,
        "check1_dictionary_fewer_queries": dictionary_mean < random_mean,
        "sequential_mean_queries": sequential_mean,
        "sequential_successes": sequential_ok,
        "fixed_sample_size": fixed_sample_size(EPSILON),
        "fixed_mean_queries": fixed_mean,
        "fixed_successes": fixed_ok,
        "check2_fixed_over_sequential": fixed_mean / sequential_mean,
        "check3_same_plaintext": same_plaintext,
        "check3_all_same": same_plaintext == n_trials,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the Tier 2 experiments and the three D14 pattern checks.")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--trials", type=int, default=N_TRIALS)
    parser.add_argument("--output", type=Path,
                        default=Path("results/tier2_pattern_checks.csv"))
    args = parser.parse_args()

    summary = run_checks(args.seed, args.output, args.trials)
    n = summary["n_trials"]
    print(f"CSV: {args.output}")
    print(f"C0: dictionary = {summary['c0_dictionary']:.2f}, "
          f"random block = {summary['c0_random_block']:.0f} "
          f"(Canvel thresholds for p = {SUCCESS_TARGET})")
    print(f"(1) dictionary: mean {summary['dictionary_mean_queries']:.1f} queries, "
          f"{summary['dictionary_successes']}/{n} correct; "
          f"random block: mean {summary['random_block_mean_queries']:.1f} queries, "
          f"{summary['random_block_successes']}/{n} correct "
          f"-> dictionary needs fewer: {summary['check1_dictionary_fewer_queries']}")
    print(f"(2) sequential: mean {summary['sequential_mean_queries']:.1f} queries, "
          f"{summary['sequential_successes']}/{n} correct; "
          f"fixed sample (n = {summary['fixed_sample_size']}): "
          f"mean {summary['fixed_mean_queries']:.1f} queries, "
          f"{summary['fixed_successes']}/{n} correct "
          f"-> ratio {summary['check2_fixed_over_sequential']:.2f}x "
          "(Canvel: 4-5x, compared by pattern only)")
    print(f"(3) noise off: Tier 2 = Tier 1 = plaintext on "
          f"{summary['check3_same_plaintext']}/{n} full blocks "
          f"-> {summary['check3_all_same']}")


if __name__ == "__main__":
    main()
