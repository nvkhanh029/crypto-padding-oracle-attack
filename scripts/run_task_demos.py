"""Create the stub-harness result CSV."""

from __future__ import annotations

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
from padding_oracle.harness.evaluation import (  # noqa: E402
    ExperimentCase,
    run_experiment,
)


def main() -> None:
    results = ROOT / "results"
    ciphertext = fake_cbc_encrypt(b"known plaintext", bytes(16))[:32]
    expected = fake_cbc_decrypt_raw(ciphertext)[-16:]
    run_experiment(
        experiment="harness_stub_smoke",
        attack_name="stub_attack",
        oracle=FakePerfectOracle(),
        attack=stub_attack,
        cases=[ExperimentCase("stub-target", ciphertext, expected)],
        seed=42,
        output_path=results / "harness_stub_smoke.csv",
        n_bytes=16,
    )


if __name__ == "__main__":
    main()
