"""Run the reversed-trigram add-k prior experiment (T9).

Run from the repo root:
    PYTHONPATH=src python -m padding_oracle.tier3.run_reversed_trigram_experiment

Defaults: --data data/wordlist/words8.csv, --output results/reversed_trigram_results.csv.
The input CSV must have columns: word, band, split.

Steps: fit the prior on the train words only, choose k on the dev words, score
the test words once. A control row fits on the test words themselves (it leaks
the answers, so it is only an upper bound).
"""
from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter, defaultdict
from pathlib import Path

from padding_oracle.tier3.reversed_trigram_prior import ReversedTrigramPrior

BANDS = ("A", "B", "C", "D")
SPLITS = ("train", "dev", "test")
GRID_MIN_EXP = -4.0
GRID_MAX_EXP = 2.0
GRID_POINTS = 121


def read_dataset(path: Path):
    """Read and validate the supplied word/band/split CSV."""
    partitions = {split: [] for split in SPLITS}
    counts = Counter()
    seen = set()

    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        required = {"word", "band", "split"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError(f"CSV must contain columns {sorted(required)}")

        for line_number, row in enumerate(reader, start=2):
            word = row["word"]
            band = row["band"]
            split = row["split"]
            if band not in BANDS:
                raise ValueError(f"Invalid band {band!r} on line {line_number}")
            if split not in SPLITS:
                raise ValueError(f"Invalid split {split!r} on line {line_number}")
            if len(word) != 8 or not word.isascii() or not word.isalpha() or word.lower() != word:
                raise ValueError(f"Expected an 8-character lowercase ASCII word on line {line_number}")
            if word in seen:
                raise ValueError(f"Duplicate word {word!r} on line {line_number}")
            seen.add(word)
            partitions[split].append((word.encode("ascii"), band))
            counts[(band, split)] += 1

    if not all(partitions[s] for s in SPLITS):
        raise ValueError("train, dev, and test partitions must all be non-empty")
    return partitions, counts


def dev_nll(words_with_band, model):
    """Mean per-word loss in bits/byte (average over the 8 bytes, then over words)."""
    total = 0.0
    for word, _band in words_with_band:
        word_loss = 0.0
        for index, target in enumerate(word):
            word_loss += -math.log2(model.probability(word[index + 1:], target))
        total += word_loss / len(word)
    return total / len(words_with_band)


def choose_k(dev_words, model):
    """Choose k solely on dev words using a fixed log grid."""
    grid = [
        10 ** (GRID_MIN_EXP + i * (GRID_MAX_EXP - GRID_MIN_EXP) / (GRID_POINTS - 1))
        for i in range(GRID_POINTS)
    ]
    scored = []
    for k in grid:
        model.set_k(k)
        scored.append((dev_nll(dev_words, model), k))
    best_loss, best_k = min(scored)
    model.set_k(best_k)
    return best_k, best_loss


def summarize(word_losses, top1s, zero_flags, distinct, zero_distinct):
    """Turn the collected lists into one row of metrics."""
    return {
        "n_words": len(word_losses),
        "bits_per_byte": sum(word_losses) / len(word_losses),
        "expected_top1": sum(top1s) / len(top1s),
        "zero_trigram_occurrences": sum(zero_flags),
        "trigram_occurrences": len(zero_flags),
        "zero_trigram_occurrence_share": sum(zero_flags) / len(zero_flags),
        "distinct_test_trigrams": len(distinct),
        "zero_distinct_test_trigrams": len(zero_distinct),
        "zero_distinct_trigram_share": len(zero_distinct) / len(distinct),
    }


def evaluate(words_with_band, model):
    """Score words (uniform weights) with a fitted model.

    A "zero-count trigram" is a (two-byte right context, target byte) pair that
    never occurs in the model's training words. Every one of the 8 positions of
    a word has such a context (the word end is padded with boundary bytes).
    """
    groups = {"ALL": ([], [], [], set(), set())}
    for band in BANDS:
        groups[band] = ([], [], [], set(), set())

    for word, band in words_with_band:
        loss = 0.0
        top1_sum = 0.0
        zero_flags = []
        pairs = []
        for index, target in enumerate(word):
            suffix = word[index + 1:]
            counter = model.context_counts(suffix)
            loss += -math.log2(model.probability(suffix, target))

            # Expected top-1 hit rate with uniform random tie-breaking.
            maximum = max(counter.values()) if counter else 0
            target_count = counter.get(target, 0)
            if target_count == maximum:
                ties = sum(1 for v in counter.values() if v == maximum) if maximum else 256
                top1_sum += 1.0 / ties

            zero_flags.append(target_count == 0)
            pairs.append((model.context(suffix), target))

        for name in ("ALL", band):
            losses, top1s, zeros, distinct, zero_distinct = groups[name]
            losses.append(loss / len(word))
            top1s.append(top1_sum / len(word))
            zeros.extend(zero_flags)
            for pair, is_zero in zip(pairs, zero_flags):
                distinct.add(pair)
                if is_zero:
                    zero_distinct.add(pair)

    result = summarize(*groups["ALL"])
    result["per_band"] = {
        band: summarize(*groups[band]) for band in BANDS if groups[band][0]
    }
    return result


def write_results_csv(path, k, main, control):
    """Write overall and per-band rows for the main model and leakage control."""
    fields = [
        "model", "band", "n_words", "k", "bits_per_byte", "expected_top1",
        "zero_trigram_occurrences", "trigram_occurrences",
        "zero_trigram_occurrence_share", "distinct_test_trigrams",
        "zero_distinct_test_trigrams", "zero_distinct_trigram_share",
    ]
    rows = []
    for name, result in (("train_only", main), ("train = test (leakage control)", control)):
        scopes = [("ALL", result)] + list(result["per_band"].items())
        for band, metrics in scopes:
            rows.append({
                "model": name,
                "band": band,
                "n_words": metrics["n_words"],
                "k": f"{k:.15g}",
                "bits_per_byte": f'{metrics["bits_per_byte"]:.8f}',
                "expected_top1": f'{metrics["expected_top1"]:.8f}',
                "zero_trigram_occurrences": metrics["zero_trigram_occurrences"],
                "trigram_occurrences": metrics["trigram_occurrences"],
                "zero_trigram_occurrence_share": f'{metrics["zero_trigram_occurrence_share"]:.8f}',
                "distinct_test_trigrams": metrics["distinct_test_trigrams"],
                "zero_distinct_test_trigrams": metrics["zero_distinct_test_trigrams"],
                "zero_distinct_trigram_share": f'{metrics["zero_distinct_trigram_share"]:.8f}',
            })
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data", type=Path, default=Path("data/wordlist/words8.csv"))
    parser.add_argument("--output", type=Path, default=Path("results/reversed_trigram_results.csv"))
    args = parser.parse_args()

    partitions, split_counts = read_dataset(args.data)
    train_words = [word for word, _ in partitions["train"]]
    dev_words = partitions["dev"]
    test_words = partitions["test"]

    # Fit on train only, choose k on dev, score the test words once.
    model = ReversedTrigramPrior(train_words, k=1.0)
    k, dev_loss = choose_k(dev_words, model)
    main_result = evaluate(test_words, model)

    # Explicit leakage control: fit on the test words themselves and score them.
    control_model = ReversedTrigramPrior([word for word, _ in test_words], k)
    control_result = evaluate(test_words, control_model)

    # Sanity check of the public interface: 256 positive values that sum to 1.
    for suffix in (b"", b"a", b"ab", b"abcdefg"):
        probabilities = model.prior(suffix)
        assert len(probabilities) == 256
        assert all(value > 0.0 for value in probabilities)
        assert math.isclose(sum(probabilities), 1.0, rel_tol=1e-12, abs_tol=1e-12)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_results_csv(args.output, k, main_result, control_result)

    summary = {
        "k": k,
        "dev_bits_per_byte": dev_loss,
        "train_words": len(train_words),
        "dev_words": len(dev_words),
        "test_words": len(test_words),
        "split_counts": {f"{band}/{split}": split_counts[(band, split)]
                         for band in BANDS for split in SPLITS},
        "main_test": main_result,
        "train_equals_test_control": control_result,
        "results_csv": str(args.output),
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
