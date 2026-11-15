"""Smoke tests for T12b: the Tier 3 experiment runner and chart."""

import csv

import pytest

from padding_oracle.tier3.experiments import (
    ExperimentConfig,
    _summarize,
    run_experiments,
)

WORDS = {
    "A": ("aardvark", "abandons", "abacuses"),
    "B": ("aardwolf", "abactors", "abattoir"),
    "C": ("aasvogel", "abbacies", "abducent"),
    "D": ("aberrant", "abetters", "abettals"),
}


def _write_data(path):
    rows = []
    for band, words in WORDS.items():
        for word, split in zip(words, ("train", "dev", "test")):
            assert len(word) == 8 and word.isalpha() and word.islower()
            rows.append({"word": word, "band": band, "split": split})
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["word", "band", "split"])
        writer.writeheader()
        writer.writerows(rows)


def _config(tmp_path, grids=(512,)):
    data = tmp_path / "words8.csv"
    _write_data(data)
    return ExperimentConfig(
        data=data,
        output=tmp_path / "raw.csv",
        summary=tmp_path / "summary.csv",
        chart_data=tmp_path / "chart.csv",
        matched=tmp_path / "matched.csv",
        figure=tmp_path / "chart.pdf",
        per_band=1,
        grids=grids,
        backend="fake",
        noise=False,
        target_error=1.0,
    )


def test_smoke_experiment_writes_contract_csv_and_summary(tmp_path):
    config = _config(tmp_path)
    result = run_experiments(config)

    assert result["n_rows"] > 0
    with config.output.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
    assert reader.fieldnames == [
        "experiment", "attack", "oracle", "seed", "target", "band",
        "bytes_attacked", "queries", "success", "params",
    ]
    assert {row["experiment"] for row in rows} == {
        "tier3_main", "tier3_train_equals_test", "tier3_random_bytes",
    }
    assert all(int(row["bytes_attacked"]) == 8 for row in rows)

    with config.summary.open(encoding="utf-8", newline="") as handle:
        summary = list(csv.DictReader(handle))
    assert summary
    # Random targets have an empty band and must count once in the ALL scope.
    random_all = [
        row for row in summary
        if row["experiment"] == "tier3_random_bytes"
        and row["scope"] == "all"
        and row["attack"] == "posterior_trigram"
    ]
    assert random_all[0]["n"] == "4"

    with config.chart_data.open(encoding="utf-8", newline="") as handle:
        chart = list(csv.DictReader(handle))
    assert chart

    assert config.figure.read_bytes().startswith(b"%PDF-1.4")


def test_sequential_halving_is_skipped_below_its_minimum(tmp_path):
    config = _config(tmp_path, grids=(512,))
    run_experiments(config)
    with config.output.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert not [row for row in rows if row["attack"] == "sequential_halving"]


def test_sequential_halving_runs_at_its_minimum(tmp_path):
    config = _config(tmp_path, grids=(16_384,))
    run_experiments(config)
    with config.output.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    sh_rows = [row for row in rows if row["attack"] == "sequential_halving"]
    assert sh_rows
    assert all(int(row["queries"]) <= 16_384 for row in sh_rows)


def test_bad_config_is_rejected(tmp_path):
    base = _config(tmp_path)
    with pytest.raises(ValueError):
        run_experiments(
            ExperimentConfig(**{**base.__dict__, "per_band": 0})
        )
    with pytest.raises(ValueError):
        run_experiments(
            ExperimentConfig(**{**base.__dict__, "grids": ()})
        )


def test_summary_parses_the_grid_and_avoids_duplicate_all_rows():
    rows = [
        {
            "experiment": "x", "attack": "a", "band": "A",
            "queries": 10, "success": 1,
            "params": "max_queries=100;seed=42",
        },
        {
            "experiment": "x", "attack": "a", "band": "",
            "queries": 20, "success": 0,
            "params": "max_queries=100;seed=42",
        },
    ]
    summary = _summarize(rows)
    all_rows = [row for row in summary if row["scope"] == "all"]
    assert len(all_rows) == 1
    assert all_rows[0]["n"] == 2
    assert all_rows[0]["success_rate"] == 0.5
