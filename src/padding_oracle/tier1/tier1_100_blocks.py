"""Run the 100-block Tier 1 reproduction experiment with real AES-CBC.

From the repository root:
    $env:PYTHONPATH = "src"
    python -m padding_oracle.tier1.tier1_100_blocks --seed 20261109
"""
from __future__ import annotations

import argparse
import csv
import random
import statistics
from pathlib import Path

from padding_oracle.core.contracts import BLOCK_SIZE, CSV_COLUMNS
from padding_oracle.tier1.aes import aes_cbc_encrypt
from padding_oracle.tier1.attack import attack
from padding_oracle.tier1.oracle import AESPerfectOracle

DEFAULT_SEED = 20261109
N_BLOCKS = 100
AES_KEY_SIZE = 16
ACCEPTANCE_LOW = 128 * 0.95
ACCEPTANCE_HIGH = 128 * 1.05


def random_bytes(rng: random.Random, length: int) -> bytes:
    """Generate deterministic bytes using the supplied RNG."""
    return bytes(rng.getrandbits(8) for _ in range(length))


def run_experiment(seed: int, output_path: Path) -> dict[str, float | int | bool]:
    """Run 100 attacks, write required CSV rows, and return measured statistics."""
    rng = random.Random(seed)
    # Reuse one deterministic AES key for all 100 targets.
    key = random_bytes(rng, AES_KEY_SIZE)
    rows = []
    byte_query_counts = []
    successes = 0

    for target_number in range(1, N_BLOCKS + 1):
        plaintext = random_bytes(rng, BLOCK_SIZE)
        iv = random_bytes(rng, BLOCK_SIZE)

        # aes_cbc_encrypt returns IV || ciphertext. The attack targets C1 only.
        encrypted = aes_cbc_encrypt(plaintext, key, iv)
        challenge = encrypted[:2 * BLOCK_SIZE]  # IV || C1

        oracle = AESPerfectOracle(key)
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