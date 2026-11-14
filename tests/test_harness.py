import csv
import logging

import pytest

from padding_oracle.core.contracts import AttackFailure, CSV_COLUMNS
from padding_oracle.core.fakes import (
    FakePerfectOracle,
    fake_cbc_decrypt_raw,
    fake_cbc_encrypt,
    stub_attack,
)
from padding_oracle.harness.evaluation import ExperimentCase, run_experiment
from padding_oracle.tier1.aes import aes_cbc_encrypt
from padding_oracle.tier1.attack import attack as vaudenay_attack
from padding_oracle.tier1.oracle import AESPerfectOracle
from padding_oracle.tier2 import (
    GaussianTimingOracle,
    dictionary_attack,
    wald_thresholds,
)


def _case(target="sample"):
    ciphertext = fake_cbc_encrypt(b"known plaintext", bytes(16))[:32]
    expected = fake_cbc_decrypt_raw(ciphertext)[-16:]
    return ExperimentCase(target, ciphertext, expected)


def test_stub_harness_writes_contract_csv(tmp_path):
    output = tmp_path / "nested" / "stub-results.csv"
    rows = run_experiment(
        experiment="harness_stub",
        attack_name="stub_attack",
        oracle=FakePerfectOracle(),
        attack=stub_attack,
        cases=[_case()],
        seed=42,
        output_path=output,
        n_bytes=16,
        attack_params={"threshold": 0.5},
    )

    assert rows == [{
        "experiment": "harness_stub",
        "attack": "stub_attack",
        "oracle": "FakePerfectOracle",
        "seed": 42,
        "target": "sample",
        "band": "",
        "bytes_attacked": 16,
        "queries": 1,
        "success": 0,
        "params": "threshold=0.5",
    }]
    with output.open(encoding="utf-8", newline="") as result_file:
        reader = csv.DictReader(result_file)
        assert reader.fieldnames == CSV_COLUMNS
        assert next(reader)["success"] == "0"
        assert list(reader) == []


def test_harness_runs_tier1_attack(tmp_path):
    key = bytes(range(16))
    plaintext = bytes(range(16))
    ciphertext = aes_cbc_encrypt(plaintext, key, bytes(16))[:32]
    output = tmp_path / "tier1.csv"

    rows = run_experiment(
        experiment="tier1_harness",
        attack_name="vaudenay",
        oracle=AESPerfectOracle(key),
        attack=vaudenay_attack,
        cases=[ExperimentCase("random-block", ciphertext, plaintext)],
        seed=42,
        output_path=output,
        n_bytes=16,
    )

    assert rows[0]["success"] == 1
    assert rows[0]["queries"] > 0
    with output.open(encoding="utf-8", newline="") as result_file:
        row = next(csv.DictReader(result_file))
    assert row["attack"] == "vaudenay"
    assert row["success"] == "1"


def test_harness_runs_tier2_dictionary_attack(tmp_path):
    key = bytes(range(16))
    word = "password"
    plaintext = b"filler12" + word.encode("ascii")
    ciphertext = aes_cbc_encrypt(plaintext, key, bytes(16))[:32]
    oracle = GaussianTimingOracle(AESPerfectOracle(key), seed=42, noise=False)
    tau_lo, tau_hi = wald_thresholds(0.01, 0.01)
    output = tmp_path / "tier2.csv"

    rows = run_experiment(
        experiment="tier2_harness_noise_off",
        attack_name="dictionary_attack",
        oracle=oracle,
        attack=dictionary_attack,
        cases=[ExperimentCase(word, ciphertext, word.encode("ascii"), band="A")],
        seed=42,
        output_path=output,
        n_bytes=8,
        attack_params={
            "tau_lo": tau_lo,
            "tau_hi": tau_hi,
            "words": ["mountain", word, "sandwich"],
        },
    )

    assert rows[0]["success"] == 1
    assert rows[0]["queries"] > 0
    with output.open(encoding="utf-8", newline="") as result_file:
        row = next(csv.DictReader(result_file))
    assert row["attack"] == "dictionary_attack"
    assert row["success"] == "1"
    assert row["band"] == "A"
    assert row["params"].endswith("words=3 candidates")


def test_harness_resets_query_counter_for_each_case(tmp_path):
    rows = run_experiment(
        experiment="stub",
        attack_name="stub_attack",
        oracle=FakePerfectOracle(),
        attack=stub_attack,
        cases=[_case("one"), _case("two")],
        seed=0,
        output_path=tmp_path / "results.csv",
        n_bytes=16,
    )

    assert [row["queries"] for row in rows] == [1, 1]


def test_harness_raises_when_attack_exceeds_max_queries(tmp_path):
    def three_query_attack(oracle, ciphertext, n_bytes, **params):
        assert "max_queries" not in params
        for _ in range(3):
            oracle.query(ciphertext)
        return bytes(n_bytes)

    with pytest.raises(
        RuntimeError,
        match=r"target 'budget-target'.*3 queries.*max_queries budget 2",
    ):
        run_experiment(
            experiment="budget",
            attack_name="three_query_attack",
            oracle=FakePerfectOracle(),
            attack=three_query_attack,
            cases=[_case("budget-target")],
            seed=0,
            output_path=tmp_path / "budget.csv",
            n_bytes=16,
            attack_params={"max_queries": 2},
        )


def test_attack_failure_is_recorded_and_logged(tmp_path, caplog):
    def unavailable_attack(oracle, ciphertext, n_bytes, **params):
        oracle.query(ciphertext)
        raise AttackFailure("not enough observations")

    with caplog.at_level(logging.WARNING):
        rows = run_experiment(
            experiment="failure",
            attack_name="unavailable",
            oracle=FakePerfectOracle(),
            attack=unavailable_attack,
            cases=[_case()],
            seed=0,
            output_path=tmp_path / "failure.csv",
            n_bytes=16,
        )

    assert rows[0]["success"] == 0
    assert rows[0]["queries"] == 1
    assert "not enough observations" in caplog.text


@pytest.mark.parametrize(
    ("cases", "n_bytes", "message"),
    [
        ([], 16, "at least one target"),
        ([_case()], 0, "n_bytes must be positive"),
        ([_case()], 8, "expected truth must contain 8 bytes"),
    ],
)
def test_invalid_experiment_is_rejected(tmp_path, cases, n_bytes, message):
    with pytest.raises(ValueError, match=message):
        run_experiment(
            experiment="invalid",
            attack_name="stub",
            oracle=FakePerfectOracle(),
            attack=stub_attack,
            cases=cases,
            seed=0,
            output_path=tmp_path / "invalid.csv",
            n_bytes=n_bytes,
        )


def test_unexpected_attack_errors_propagate(tmp_path):
    def broken_attack(oracle, ciphertext, n_bytes, **params):
        raise RuntimeError("unexpected failure")

    output = tmp_path / "not-written.csv"
    with pytest.raises(RuntimeError, match="unexpected failure"):
        run_experiment(
            experiment="unexpected",
            attack_name="broken",
            oracle=FakePerfectOracle(),
            attack=broken_attack,
            cases=[_case()],
            seed=0,
            output_path=output,
            n_bytes=16,
        )

    assert not output.exists()
