"""Run the reversed-trigram add-k prior experiment.

Example:
    python run_reversed_trigram_experiment.py \
        --data words8.csv \
        --output reversed_trigram_results.csv \
        --report reversed_trigram_report.md

The input CSV must have columns: word, band, split.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter, defaultdict
from pathlib import Path

from reversed_trigram_prior import ReversedTrigramPrior

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


def count_contexts(words):
    """Count target bytes for empty, one-byte, and two-byte right contexts."""
    unigram = Counter()
    bigram = defaultdict(Counter)
    trigram = defaultdict(Counter)
    for word in words:
        for index, target in enumerate(word):
            suffix = word[index + 1:]
            unigram[target] += 1
            if len(suffix) >= 1:
                bigram[suffix[:1]][target] += 1
            if len(suffix) >= 2:
                trigram[suffix[:2]][target] += 1
    return unigram, bigram, trigram


def context_counter(counts, suffix):
    unigram, bigram, trigram = counts
    if len(suffix) >= 2:
        return trigram.get(suffix[:2], {})
    if len(suffix) == 1:
        return bigram.get(suffix[:1], {})
    return unigram


def dev_nll(words_with_band, counts, k):
    """Mean per-word NLL in bits/byte; all words are exactly eight bytes."""
    total = 0.0
    word_count = 0
    for word, _band in words_with_band:
        word_loss = 0.0
        for index, target in enumerate(word):
            suffix = word[index + 1:]
            counter = context_counter(counts, suffix)
            numerator = counter.get(target, 0) + k
            denominator = sum(counter.values()) + 256 * k
            word_loss += -math.log2(numerator / denominator)
        total += word_loss / len(word)
        word_count += 1
    return total / word_count


def choose_k(dev_words, train_counts):
    """Choose k solely on dev words using a fixed, documented log grid."""
    grid = [
        10 ** (GRID_MIN_EXP + i * (GRID_MAX_EXP - GRID_MIN_EXP) / (GRID_POINTS - 1))
        for i in range(GRID_POINTS)
    ]
    scored = [(dev_nll(dev_words, train_counts, k), k) for k in grid]
    best_loss, best_k = min(scored)
    return best_k, best_loss, grid


def evaluate(words_with_band, counts, k):
    """Evaluate words uniformly and collect zero-count trigram diagnostics."""
    word_losses = []
    byte_top1 = []
    trigram_zero = []
    distinct_trigrams = set()
    zero_distinct = set()
    per_band_words = defaultdict(list)
    per_band_top1 = defaultdict(list)
    per_band_zero = defaultdict(list)
    per_band_distinct = defaultdict(set)
    per_band_zero_distinct = defaultdict(set)

    for word, band in words_with_band:
        loss = 0.0
        top1_sum = 0.0
        for index, target in enumerate(word):
            suffix = word[index + 1:]
            counter = context_counter(counts, suffix)
            context_total = sum(counter.values())
            target_count = counter.get(target, 0)
            denominator = context_total + 256 * k
            probability = (target_count + k) / denominator
            loss += -math.log2(probability)

            # Expected top-1 hit rate under uniform random tie-breaking.
            maximum = max(counter.values()) if counter else 0
            if target_count == maximum:
                tie_count = sum(1 for value in counter.values() if value == maximum)
                if maximum == 0:
                    tie_count = 256
                top1_sum += 1.0 / tie_count

            if len(suffix) >= 2:
                trigram_key = (suffix[:2], target)
                is_zero = target_count == 0
                trigram_zero.append(is_zero)
                distinct_trigrams.add(trigram_key)
                per_band_distinct[band].add(trigram_key)
                if is_zero:
                    zero_distinct.add(trigram_key)
                    per_band_zero_distinct[band].add(trigram_key)
                per_band_zero[band].append(is_zero)

        word_loss = loss / len(word)
        word_top1 = top1_sum / len(word)
        word_losses.append(word_loss)
        byte_top1.append(word_top1)
        per_band_words[band].append(word_loss)
        per_band_top1[band].append(word_top1)

    result = {
        "n_words": len(words_with_band),
        "bits_per_byte": sum(word_losses) / len(word_losses),
        "expected_top1": sum(byte_top1) / len(byte_top1),
        "zero_trigram_occurrences": sum(trigram_zero),
        "trigram_occurrences": len(trigram_zero),
        "zero_trigram_occurrence_share": sum(trigram_zero) / len(trigram_zero),
        "distinct_test_trigrams": len(distinct_trigrams),
        "zero_distinct_test_trigrams": len(zero_distinct),
        "zero_distinct_trigram_share": len(zero_distinct) / len(distinct_trigrams),
        "per_band": {},
    }

    for band in BANDS:
        if band not in per_band_words:
            continue
        zeros = per_band_zero[band]
        distinct = per_band_distinct[band]
        zero_distinct_band = per_band_zero_distinct[band]
        result["per_band"][band] = {
            "n_words": len(per_band_words[band]),
            "bits_per_byte": sum(per_band_words[band]) / len(per_band_words[band]),
            "expected_top1": sum(per_band_top1[band]) / len(per_band_top1[band]),
            "zero_trigram_occurrences": sum(zeros),
            "trigram_occurrences": len(zeros),
            "zero_trigram_occurrence_share": sum(zeros) / len(zeros),
            "distinct_test_trigrams": len(distinct),
            "zero_distinct_test_trigrams": len(zero_distinct_band),
            "zero_distinct_trigram_share": len(zero_distinct_band) / len(distinct),
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


def make_report(path, split_counts, k, dev_loss, main, control):
    """Write a concise reproducibility report."""
    lines = [
        "# Reversed trigram prior with add-k smoothing",
        "",
        "## Dataset and split",
        "",
        "Input: `words8.csv`. All records were validated as unique, lowercase ASCII words of exactly eight bytes.",
        "The supplied `split` column was used unchanged; no reshuffling or resplitting was performed.",
        "",
        "| Band | Train | Dev | Test |",
        "|---|---:|---:|---:|",
    ]
    for band in BANDS:
        lines.append("| " + band + " | " + " | ".join(
            str(split_counts[(band, split)]) for split in SPLITS
        ) + " |")
    lines += [
        "| **Total** | **{}** | **{}** | **{}** |".format(
            sum(split_counts[("A", s)] + split_counts[("B", s)] +
                split_counts[("C", s)] + split_counts[("D", s)] for s in SPLITS)
            if False else sum(split_counts[(b, "train")] for b in BANDS),
            sum(split_counts[(b, "dev")] for b in BANDS),
            sum(split_counts[(b, "test")] for b in BANDS),
        ),
        "",
        "## Model definition",
        "",
        "The prior predicts the byte immediately left of the recovered suffix. Suffix bytes are ordered nearest-to-farthest.",
        "- Empty suffix: unigram distribution.",
        "- One-byte suffix: bigram conditional distribution.",
        "- Two or more suffix bytes: trigram conditional distribution using the first two suffix bytes.",
        "- Alphabet: all 256 byte values.",
        "- Add-k: `P(b|s) = (C(s,b) + k) / (C(s) + 256k)`, so every probability is strictly positive.",
        "- Train-only model: counts are fitted exclusively on the 25,426 training words.",
        "",
        "## Dev tuning",
        "",
        f"Chosen `k = {k:.15g}` from a fixed grid of {GRID_POINTS} logarithmically spaced values between 1e-4 and 1e2.",
        f"Selection objective: minimum dev average negative log-likelihood = {dev_loss:.8f} bits/byte, averaging positions within each word and then words uniformly.",
        "",
        "## Test results",
        "",
        "| Model | Words | Bits/byte (NLL) | Expected top-1 | Zero-count trigram occurrences | Share | Distinct zero-count trigram types | Share |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, result in (("Train only", main), ("Train = test (leakage control)", control)):
        lines.append(
            f"| {name} | {result['n_words']} | {result['bits_per_byte']:.6f} | "
            f"{result['expected_top1']:.4%} | {result['zero_trigram_occurrences']:,}/"
            f"{result['trigram_occurrences']:,} | {result['zero_trigram_occurrence_share']:.4%} | "
            f"{result['zero_distinct_test_trigrams']:,}/{result['distinct_test_trigrams']:,} | "
            f"{result['zero_distinct_trigram_share']:.4%} |"
        )
    lines += [
        "",
        "The test set was evaluated once for the train-only model after k selection. The control deliberately fits on the test words and evaluates on those same words; it leaks the answers and is not a valid held-out estimate. The control reuses the dev-selected k.",
        "",
        "## Per-band side analysis (train-only model)",
        "",
        "| Band | Test words | Bits/byte (NLL) | Expected top-1 | Zero-count trigram occurrence share | Distinct zero-count trigram share |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for band in BANDS:
        m = main["per_band"][band]
        lines.append(
            f"| {band} | {m['n_words']:,} | {m['bits_per_byte']:.6f} | "
            f"{m['expected_top1']:.4%} | {m['zero_trigram_occurrence_share']:.4%} | "
            f"{m['zero_distinct_trigram_share']:.4%} |"
        )
    lines += [
        "",
        "## Interpretation notes",
        "",
        "- `bits/byte` is the mean byte negative log-likelihood in bits; lower is better.",
        "- `Expected top-1` gives ties uniform random tie-breaking, avoiding arbitrary wins from byte ordering.",
        "- Occurrence share counts every eligible test position (the first six positions per eight-byte word have two or more bytes to their right).",
        "- Distinct-type share counts unique `(two-byte suffix, target byte)` combinations in the test set.",
        "- The zero-count trigram diagnostic concerns the exact two-byte-context trigram count in training; add-k still assigns it nonzero probability.",
        "",
        "## Reproducibility",
        "",
        "No random split or random sampling was performed by this script. The dataset's existing split assignments were retained. The fixed k grid is embedded in the script.",
        "",
        "The callable prior implementation is in `reversed_trigram_prior.py`; `prior(suffix)` returns 256 probabilities indexed by byte value 0 through 255.",
    ]
    path.write_text("\\n".join(lines) + "\\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path("words8.csv"))
    parser.add_argument("--output", type=Path, default=Path("reversed_trigram_results.csv"))
    parser.add_argument("--report", type=Path, default=Path("reversed_trigram_report.md"))
    args = parser.parse_args()

    partitions, split_counts = read_dataset(args.data)
    train_words = [word for word, _ in partitions["train"]]
    dev_words = partitions["dev"]
    test_words = partitions["test"]

    train_counts = count_contexts(train_words)
    k, dev_loss, _grid = choose_k(dev_words, train_counts)

    # Main held-out evaluation: fit on train only, tune on dev, test once.
    main_result = evaluate(test_words, train_counts, k)

    # Explicit leakage control: fit on test itself and score those same words.
    test_words_only = [word for word, _ in test_words]
    control_counts = count_contexts(test_words_only)
    control_result = evaluate(test_words, control_counts, k)

    # Exercise the public prior interface and verify all 256 probabilities are positive.
    prior_model = ReversedTrigramPrior(train_words, k)
    for suffix in (b"", b"a", b"ab", b"abcdefgh"):
        probabilities = prior_model.prior(suffix)
        assert len(probabilities) == 256
        assert all(value > 0.0 for value in probabilities)
        assert math.isclose(sum(probabilities), 1.0, rel_tol=1e-12, abs_tol=1e-12)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    write_results_csv(args.output, k, main_result, control_result)
    make_report(args.report, split_counts, k, dev_loss, main_result, control_result)

    summary = {
        "k": k,
        "dev_bits_per_byte": dev_loss,
        "train_words": len(train_words),
        "dev_words": len(dev_words),
        "test_words": len(test_words),
        "main_test": main_result,
        "train_equals_test_control": control_result,
        "results_csv": str(args.output),
        "report": str(args.report),
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
