import csv
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_wordlist_has_expected_counts_sort_order_and_splits():
    with (ROOT / "data" / "wordlist" / "words8.csv").open(
        encoding="utf-8", newline=""
    ) as source:
        rows = list(csv.DictReader(source))

    assert len(rows) == 36_322
    assert [row["word"] for row in rows] == sorted(row["word"] for row in rows)
    assert Counter(row["band"] for row in rows) == {
        "A": 12_750, "B": 6_747, "C": 8_331, "D": 8_494
    }
    assert Counter((row["band"], row["split"]) for row in rows) == {
        ("A", "train"): 8_925, ("A", "dev"): 1_275, ("A", "test"): 2_550,
        ("B", "train"): 4_723, ("B", "dev"): 675, ("B", "test"): 1_349,
        ("C", "train"): 5_832, ("C", "dev"): 833, ("C", "test"): 1_666,
        ("D", "train"): 5_946, ("D", "dev"): 849, ("D", "test"): 1_699,
    }
    assert all(
        len(row["word"]) == 8
        and row["word"].isascii()
        and row["word"].isalpha()
        and row["word"].islower()
        for row in rows
    )
