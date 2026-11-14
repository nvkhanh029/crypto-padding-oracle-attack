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
