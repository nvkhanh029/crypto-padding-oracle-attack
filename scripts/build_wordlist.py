"""Build the stratified eight-letter SCOWL word list."""

from __future__ import annotations

import argparse
import csv
import random
from pathlib import Path


EXPECTED_LINES = {60: 109_140, 70: 166_817, 80: 241_867, 85: 298_937}
EXPECTED_BANDS = {"A": 12_750, "B": 6_747, "C": 8_331, "D": 8_494}
SEED = 42


def _read_words(path: Path, expected_count: int) -> set[str]:
    words = path.read_text(encoding="utf-8-sig").splitlines()
    if len(words) != expected_count:
        raise ValueError(
            f"{path.name}: expected {expected_count} lines, found {len(words)}"
        )
    if len(words) != len(set(words)):
        raise ValueError(f"{path.name}: duplicate entries found")
    return set(words)


def build_wordlist(source_dir: Path, output_path: Path, seed: int = SEED) -> dict[str, int]:
    lists = {
        size: _read_words(source_dir / f"wl{size}.txt", expected_count)
        for size, expected_count in EXPECTED_LINES.items()
    }
    if not (lists[60] <= lists[70] <= lists[80] <= lists[85]):
        raise ValueError("SCOWL source lists are not nested as expected")

    band_words = {
        "A": lists[60],
        "B": lists[70] - lists[60],
        "C": lists[80] - lists[70],
        "D": lists[85] - lists[80],
    }
    rng = random.Random(seed)
    split_by_word: dict[str, str] = {}
    for band, words in band_words.items():
        filtered = sorted(
            word for word in words
            if len(word) == 8 and word.isascii() and word.isalpha() and word.islower()
        )
        if len(filtered) != EXPECTED_BANDS[band]:
            raise ValueError(
                f"Band {band}: expected {EXPECTED_BANDS[band]} words, found {len(filtered)}"
            )
        rng.shuffle(filtered)
        train_count = round(len(filtered) * 0.70)
        dev_count = round(len(filtered) * 0.10)
        for word in filtered[:train_count]:
            split_by_word[word] = "train"
        for word in filtered[train_count:train_count + dev_count]:
            split_by_word[word] = "dev"
        for word in filtered[train_count + dev_count:]:
            split_by_word[word] = "test"

    band_by_word = {
        word: band
        for band, words in band_words.items()
        for word in words
        if word in split_by_word
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(["word", "band", "split"])
        writer.writerows(
            (word, band_by_word[word], split_by_word[word])
            for word in sorted(split_by_word)
        )
    return {
        f"{band}_{split}": sum(
            1 for word in band_words[band]
            if word in split_by_word and split_by_word[word] == split
        )
        for band in band_words
        for split in ("train", "dev", "test")
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True, help="directory with wl60/70/80/85.txt")
    parser.add_argument("--output", type=Path, default=Path("data/wordlist/words8.csv"))
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()
    sizes = build_wordlist(args.source_dir, args.output, args.seed)
    print(f"Wrote {sum(sizes.values()):,} words to {args.output} (seed {args.seed}).")
    for band in EXPECTED_BANDS:
        print(
            f"{band}: {sizes[f'{band}_train']:,} train, "
            f"{sizes[f'{band}_dev']:,} dev, {sizes[f'{band}_test']:,} test"
        )


if __name__ == "__main__":
    main()
