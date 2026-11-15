"""Smoke test for the Tier 2 pattern-check script (T8b), with 2 targets per attack."""

import csv

from padding_oracle.core.contracts import BANDS, CSV_COLUMNS
from padding_oracle.tier2.tier2_pattern_checks import fixed_sample_size, run_checks

SEED = 7
N_TRIALS = 2


def test_run_checks_writes_contract_rows(tmp_path):
    output = tmp_path / "tier2_pattern_checks.csv"
    summary = run_checks(SEED, output, n_trials=N_TRIALS)

    with output.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames == CSV_COLUMNS
        rows = list(reader)

    # Check (1): 2 attacks; check (2): 2 attacks; check (3): 2 attacks.
    assert len(rows) == 6 * N_TRIALS
    for row in rows:
        assert row["seed"] == str(SEED)              # the real run seed
        assert int(row["queries"]) > 0
        assert row["success"] in ("0", "1")

    word_rows = [row for row in rows if row["attack"] == "dictionary"]
    assert len(word_rows) == N_TRIALS
    for row in word_rows:
        assert len(row["target"]) == 8               # the word itself
        assert row["band"] in BANDS
        assert row["bytes_attacked"] == "8"

    # Noise off is deterministic: Tier 2 must match Tier 1 on every block.
    noise_off = [row for row in rows if row["experiment"] == "tier2_noise_off"]
    assert len(noise_off) == 2 * N_TRIALS
    assert all(row["success"] == "1" for row in noise_off)
    assert all(row["bytes_attacked"] == "16" for row in noise_off)
    assert summary["check3_all_same"] is True


def test_same_seed_gives_the_same_csv(tmp_path):
    first = tmp_path / "first.csv"
    second = tmp_path / "second.csv"
    run_checks(SEED, first, n_trials=1)
    run_checks(SEED, second, n_trials=1)
    assert first.read_bytes() == second.read_bytes()


def test_fixed_sample_size_grows_when_the_error_rate_shrinks():
    assert fixed_sample_size(0.001) > fixed_sample_size(0.01) > fixed_sample_size(0.1)
