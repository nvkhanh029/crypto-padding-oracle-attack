"""Smoke tests for T0b: the create-block -> run-attack -> write-CSV pipeline.

These use only the T0a fakes and the stub attack, so they run in seconds and
need no AES library. They prove the plumbing works end to end:
  1. build a ciphertext and query the oracle (the counter moves);
  2. run an attack through the Attack shape (the stub stands in until T4);
  3. write a results CSV with exactly the contract columns and read it back.

The real Tier 1 attack test arrives with T4. Keep these passing.
"""

import csv

from padding_oracle.core import contracts as c
from padding_oracle.core import fakes as f


def test_create_block_and_perfect_oracle_pipeline():
    # 1. create a block (IV + one block); 2. query the perfect oracle.
    ct = f.fake_cbc_encrypt(b"smoke test", bytes(16))
    oracle = f.FakePerfectOracle()

    assert oracle.query(ct) is True          # untouched ciphertext: padding valid

    tampered = bytearray(ct)
    tampered[-1] ^= 0x01                      # change the last byte
    oracle.query(bytes(tampered))            # may be valid or not; here we only run it
    assert oracle.queries == 2               # every call is counted exactly once


def test_attack_shape_runs_and_oracle_counts():
    # Run an attack through the Attack shape on a two-block ciphertext.
    # The real Tier 1 attack (T4) is not merged yet, so the stub stands in.
    two_blocks = f.fake_cbc_encrypt(b"x" * 8, bytes(16))[:32]
    oracle = f.FakeNoisyOracle(seed=0)

    recovered = f.stub_attack(oracle, two_blocks, 8)
    assert len(recovered) == 8               # returns n_bytes bytes
    assert oracle.queries >= 1               # cost is read from the oracle, not counted by us


def test_write_and_read_results_csv(tmp_path):
    # 3. write an output file in the contract CSV format, then read it back.
    out = tmp_path / "smoke.csv"
    row = {
        "experiment": "smoke",
        "attack": "stub_attack",
        "oracle": f.FakeNoisyOracle.__name__,
        "seed": 0,
        "target": "random_block_000",
        "band": "",
        "bytes_attacked": 8,
        "queries": 1,
        "success": 0,
        "params": "",
    }
    # newline="" keeps the CSV clean on Windows (no extra blank lines).
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=c.CSV_COLUMNS)
        writer.writeheader()
        writer.writerow(row)

    with out.open(newline="", encoding="utf-8") as fh:
        header = next(csv.reader(fh))
    assert header == c.CSV_COLUMNS           # columns present, in the exact order