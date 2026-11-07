"""Create the stub-harness and countermeasure attack result CSVs."""

from __future__ import annotations

import os
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
from padding_oracle.countermeasures.servers import (  # noqa: E402
    AesGcmServer,
    EncryptThenMacServer,
)
from padding_oracle.harness.evaluation import (  # noqa: E402
    ExperimentCase,
    run_experiment,
    run_tier1_experiment,
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

    etm = EncryptThenMacServer(os.urandom(16), os.urandom(32))
    etm_envelope = etm.seal(b"countermeasure", iv=bytes(16))
    run_tier1_experiment(
        experiment="countermeasure_tier1",
        attack_name="vaudenay",
        oracle=etm.oracle_for(etm_envelope),
        cases=[ExperimentCase("encrypt_then_mac", etm_envelope.ciphertext, b"\x00")],
        seed=42,
        output_path=results / "countermeasure_etm.csv",
        n_bytes=1,
    )

    gcm = AesGcmServer(os.urandom(16))
    gcm_envelope = gcm.seal(b"x" * 20)
    run_tier1_experiment(
        experiment="countermeasure_tier1",
        attack_name="vaudenay",
        oracle=gcm.oracle_for(gcm_envelope),
        cases=[ExperimentCase("aes_gcm", gcm_envelope.ciphertext, b"\x00")],
        seed=42,
        output_path=results / "countermeasure_gcm.csv",
        n_bytes=1,
    )


if __name__ == "__main__":
    main()
