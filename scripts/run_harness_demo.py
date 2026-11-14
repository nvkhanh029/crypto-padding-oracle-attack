"""Run the evaluation harness with stub, Tier 1, and Tier 2 attacks."""

from __future__ import annotations

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from padding_oracle.core.fakes import (  # noqa: E402
    FakePerfectOracle,
    fake_cbc_decrypt_raw,
    fake_cbc_encrypt,
    stub_attack,
)
from padding_oracle.core.contracts import BLOCK_SIZE  # noqa: E402
from padding_oracle.harness.evaluation import (  # noqa: E402
    ExperimentCase,
    run_experiment,
)
from padding_oracle.tier1.aes import aes_cbc_encrypt  # noqa: E402
from padding_oracle.tier1.attack import attack as vaudenay_attack  # noqa: E402
from padding_oracle.tier1.oracle import AESPerfectOracle  # noqa: E402
from padding_oracle.tier2 import (  # noqa: E402
    GaussianTimingOracle,
    dictionary_attack,
    load_words,
    wald_thresholds,
)

SEED = 42


def run_stub_demo(results: Path) -> None:
    ciphertext = fake_cbc_encrypt(b"known plaintext", bytes(BLOCK_SIZE))[:32]
    expected = fake_cbc_decrypt_raw(ciphertext)[-BLOCK_SIZE:]
    output_path = results / "harness_stub_smoke.csv"
    run_experiment(
        experiment="harness_stub_smoke",
        attack_name="stub_attack",
        oracle=FakePerfectOracle(),
        attack=stub_attack,
        cases=[ExperimentCase("stub-target", ciphertext, expected)],
        seed=SEED,
        output_path=output_path,
        n_bytes=BLOCK_SIZE,
    )
    print(f"Wrote stub harness results to {output_path}")


def run_tier1_demo(results: Path) -> None:
    key = bytes(range(BLOCK_SIZE))
    plaintext = bytes(range(BLOCK_SIZE))
    ciphertext = aes_cbc_encrypt(plaintext, key, bytes(BLOCK_SIZE))[:2 * BLOCK_SIZE]
    output_path = results / "tier1_harness.csv"
    run_experiment(
        experiment="tier1_harness",
        attack_name="vaudenay",
        oracle=AESPerfectOracle(key),
        attack=vaudenay_attack,
        cases=[ExperimentCase("random-block", ciphertext, plaintext)],
        seed=SEED,
        output_path=output_path,
        n_bytes=BLOCK_SIZE,
    )
    print(f"Wrote Tier 1 harness results to {output_path}")


def _test_word() -> tuple[str, str]:
    wordlist = ROOT / "data" / "wordlist" / "words8.csv"
    with wordlist.open(encoding="utf-8", newline="") as source:
        target = next(
            (row for row in csv.DictReader(source) if row["split"] == "test"),
            None,
        )
    if target is None:
        raise ValueError(f"{wordlist} contains no test words")
    return target["word"], target["band"]


def run_tier2_demo(results: Path) -> None:
    word, band = _test_word()
    key = bytes(range(BLOCK_SIZE))
    plaintext = b"filler12" + word.encode("ascii")
    ciphertext = aes_cbc_encrypt(plaintext, key, bytes(BLOCK_SIZE))[:2 * BLOCK_SIZE]
    words = load_words()
    tau_lo, tau_hi = wald_thresholds(0.01, 0.01)
    output_path = results / "tier2_harness_noise_off.csv"
    run_experiment(
        experiment="tier2_harness_noise_off",
        attack_name="dictionary_attack",
        oracle=GaussianTimingOracle(
            AESPerfectOracle(key), seed=SEED, noise=False
        ),
        attack=dictionary_attack,
        cases=[ExperimentCase(word, ciphertext, word.encode("ascii"), band)],
        seed=SEED,
        output_path=output_path,
        n_bytes=8,
        attack_params={"tau_lo": tau_lo, "tau_hi": tau_hi, "words": words},
    )
    print(f"Wrote Tier 2 harness results to {output_path}")


def main() -> None:
    results = ROOT / "results"
    run_stub_demo(results)
    run_tier1_demo(results)
    run_tier2_demo(results)


if __name__ == "__main__":
    main()
