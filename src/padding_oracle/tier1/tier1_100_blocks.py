"""Run the 100-block Tier 1 reproduction experiment.

From the repository root:
    python experiments/tier1_100_blocks.py --seed 20261109
"""
from __future__ import annotations

import argparse
import csv
import random
import statistics
from pathlib import Path

from padding_oracle.core.contracts import BLOCK_SIZE, CSV_COLUMNS
from padding_oracle.core.fakes import FakePerfectOracle, fake_cbc_encrypt
from padding_oracle.tier1.attack import attack

DEFAULT_SEED = 20261109
N_BLOCKS = 100
ACCEPTANCE_LOW = 128 * 0.95
ACCEPTANCE_HIGH = 128 * 1.05


def random_bytes(rng: random.Random, length: int) -> bytes:
    """Generate deterministic bytes using the supplied RNG."""
    return bytes(rng.getrandbits(8) for _ in range(length))


def run_experiment(seed: int, output_path: Path) -> dict[str, float | int | bool]:
    """Run 100 attacks, write required CSV rows, and return measured statistics."""
    rng = random.Random(seed)
    rows = []
    byte_query_counts = []
    successes = 0

    for target_number in range(1, N_BLOCKS + 1):
        plaintext = random_bytes(rng, BLOCK_SIZE)
        iv = random_bytes(rng, BLOCK_SIZE)
        encrypted = fake_cbc_encrypt(plaintext, iv)
        challenge = encrypted[:2 * BLOCK_SIZE]  # IV || C1

        oracle = FakePerfectOracle()
        counts = []
        recovered = attack(oracle, challenge, BLOCK_SIZE, byte_query_counts=counts)
        success = int(recovered == plaintext)
        successes += success
        byte_query_counts.extend(counts)

        rows.append({
            "experiment": "tier1_reproduction",
            "attack": "vaudenay",
            "oracle": type(oracle).__name__,
            "seed": seed,
            "target": f"random_block_{target_number:03d}",
            "band": "",
            "bytes_attacked": BLOCK_SIZE,
            "queries": oracle.queries,
            "success": success,
            "params": "",
        })

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    mean = statistics.mean(byte_query_counts)
    sample_sd = statistics.stdev(byte_query_counts)
    standard_error = sample_sd / (len(byte_query_counts) ** 0.5)
    z_975 = statistics.NormalDist().inv_cdf(0.975)
    margin = z_975 * standard_error
    ci_low, ci_high = mean - margin, mean + margin

    return {
        "blocks": len(rows),
        "bytes_attacked": len(byte_query_counts),
        "successes": successes,
        "success_rate": successes / len(rows),
        "mean_queries_per_byte": mean,
        "sample_sd_per_byte": sample_sd,
        "ci_95_low": ci_low,
        "ci_95_high": ci_high,
        "acceptance_low": ACCEPTANCE_LOW,
        "acceptance_high": ACCEPTANCE_HIGH,
        "passed_d14": ci_low >= ACCEPTANCE_LOW and ci_high <= ACCEPTANCE_HIGH,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--output", type=Path, default=Path("results/tier1_reproduction.csv"))
    args = parser.parse_args()

    summary = run_experiment(args.seed, args.output)
    print(f"CSV: {args.output}")
    for key, value in summary.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
