"""T12b: Tier 3 experiments and the success-rate chart.

Runs three attacks on the same Gaussian timing oracle and the same targets:
the posterior attack with the T9 trigram prior, NCC's uniform-prior baseline,
and Sequential Halving. Every attack receives `max_queries` as a budget for
the whole word; Sequential Halving is only run at grid values >= 16,384.

The raw CSV follows the shared CSV_COLUMNS. The summary CSV groups the raw
rows by experiment, attack, band and grid, and the chart uses the measured
`queries` column (not the grid value) on a log x-axis.

Run from the repo root:
    PYTHONPATH=src python -m padding_oracle.tier3.experiments --backend fake
Use --backend aes (the default) on a machine with PyCryptodome.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from ..core.contracts import BLOCK_SIZE, CSV_COLUMNS
from ..harness.evaluation import ExperimentCase, run_experiment
from ..tier2.noisy_oracle import GaussianTimingOracle
from .baselines import ncc_attack, sequential_halving_attack
from .chart import write_line_chart_pdf
from .posterior_attack import DELTA, posterior_attack
from .reversed_trigram_prior import ReversedTrigramPrior
from .run_reversed_trigram_experiment import choose_k, read_dataset

BANDS = ("A", "B", "C", "D")
PREFIX = b"prefix00"          # known 8-byte block prefix (D15)
KEY = bytes(range(16))
IV = bytes(16)
SH_MIN_QUERIES = 16_384
DEFAULT_GRIDS = (1024, 2048, 4096, 8192, 16_384, 32_768, 65_536, 131_072)
DEFAULT_PER_BAND = 25


@dataclass(frozen=True)
class ExperimentConfig:
    data: Path = Path("data/wordlist/words8.csv")
    output: Path = Path("results/tier3_experiments.csv")
    summary: Path = Path("results/tier3_summary.csv")
    chart_data: Path = Path("results/tier3_chart_data.csv")
    matched: Path = Path("results/tier3_matched_error.csv")
    figure: Path = Path("figures/tier3_success_vs_queries.pdf")
    per_band: int = DEFAULT_PER_BAND
    grids: tuple[int, ...] = DEFAULT_GRIDS
    seed: int = 42
    backend: str = "aes"
    k: float | None = None
    target_error: float = 0.01
    noise: bool = True


@dataclass
class _Backend:
    encrypt: Callable[[bytes], bytes]
    make_oracle: Callable[[int], GaussianTimingOracle]


def _make_backend(name: str, noise: bool) -> _Backend:
    """Build ciphertexts and the noisy oracle for the chosen implementation."""
    if name == "aes":
        from ..tier1.aes import aes_cbc_encrypt
        from ..tier1.oracle import AESPerfectOracle

        def encrypt(plain: bytes) -> bytes:
            return aes_cbc_encrypt(plain, KEY, IV)[:2 * BLOCK_SIZE]

        def make_oracle(seed: int) -> GaussianTimingOracle:
            return GaussianTimingOracle(
                AESPerfectOracle(KEY), seed=seed, noise=noise
            )

        return _Backend(encrypt, make_oracle)
    if name == "fake":
        from ..core.fakes import FakePerfectOracle, fake_cbc_encrypt

        def encrypt(plain: bytes) -> bytes:
            return fake_cbc_encrypt(plain, IV)[:2 * BLOCK_SIZE]

        def make_oracle(seed: int) -> GaussianTimingOracle:
            return GaussianTimingOracle(
                FakePerfectOracle(), seed=seed, noise=noise
            )

        return _Backend(encrypt, make_oracle)
    raise ValueError(f"unknown backend {name!r}; use 'aes' or 'fake'")


def _word_cases(
    words_with_band: Iterable[tuple[bytes, str]],
    encrypt: Callable[[bytes], bytes],
) -> list[ExperimentCase]:
    cases = []
    for word, band in words_with_band:
        plain = PREFIX + word
        cases.append(
            ExperimentCase(
                target=word.decode("ascii"),
                ciphertext=encrypt(plain),
                expected=word,
                band=band,
            )
        )
    return cases


def _random_cases(
    count: int, encrypt: Callable[[bytes], bytes], rng: random.Random
) -> list[ExperimentCase]:
    cases = []
    for index in range(count):
        word = rng.randbytes(8)
        plain = PREFIX + word
        cases.append(
            ExperimentCase(
                target=f"random_{index:03d}",
                ciphertext=encrypt(plain),
                expected=word,
                band="",
            )
        )
    return cases


def _sample_test_words(
    test_words: list[tuple[bytes, str]], per_band: int, rng: random.Random
) -> list[tuple[bytes, str]]:
    chosen = []
    for band in BANDS:
        pool = [item for item in test_words if item[1] == band]
        chosen.extend(sorted(rng.sample(pool, min(per_band, len(pool)))))
    return chosen


def _grid_from_params(text: str) -> int:
    match = re.search(r"(?:^|;)max_queries=(\d+)", text)
    if match is None:
        raise ValueError(f"no max_queries in params {text!r}")
    return int(match.group(1))


def _write_rows(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _run_group(
    *,
    config: ExperimentConfig,
    experiment: str,
    attack_name: str,
    attack: Callable,
    cases: list[ExperimentCase],
    prior_name: str,
    grid: int,
    params: dict[str, object],
    backend: _Backend,
    temp_dir: Path,
    index: int,
) -> list[dict[str, object]]:
    attack_params = dict(params)
    attack_params["max_queries"] = grid
    attack_params["seed"] = config.seed
    if prior_name:
        # Keep the prior callable itself in params; this label is only for
        # the human-readable params column.
        attack_params["prior_model"] = prior_name

    oracle = backend.make_oracle(config.seed)
    rows = run_experiment(
        experiment=experiment,
        attack_name=attack_name,
        oracle=oracle,
        attack=attack,
        cases=cases,
        seed=config.seed,
        output_path=temp_dir / f"group_{index:04d}.csv",
        n_bytes=8,
        attack_params=attack_params,
    )
    for row in rows:
        if int(row["queries"]) > grid:
            raise RuntimeError(
                f"{experiment}/{attack_name}: {row['target']} used "
                f"{row['queries']} queries above the {grid} budget"
            )
    return rows


def _summarize(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[tuple[str, str, str, int], list[dict[str, object]]] = {}
    for row in rows:
        grid = _grid_from_params(str(row["params"]))
        band = str(row["band"])
        scope_bands = ("ALL",) if band == "" else (band, "ALL")
        for scope_band in scope_bands:
            key = (str(row["experiment"]), str(row["attack"]), scope_band, grid)
            grouped.setdefault(key, []).append(row)

    summary = []
    for (experiment, attack, band, grid), group in sorted(grouped.items()):
        queries = [int(row["queries"]) for row in group]
        successes = sum(int(row["success"]) for row in group)
        summary.append({
            "experiment": experiment,
            "scope": "band" if band != "ALL" else "all",
            "band": "" if band == "ALL" else band,
            "attack": attack,
            "grid": grid,
            "n": len(group),
            "success_rate": successes / len(group),
            "error_rate": 1.0 - successes / len(group),
            "mean_queries": sum(queries) / len(queries),
            "min_queries": min(queries),
            "max_queries": max(queries),
        })
    return summary


def _write_summary(path: Path, rows: list[dict[str, object]]) -> None:
    fields = [
        "experiment", "scope", "band", "attack", "grid", "n",
        "success_rate", "error_rate", "mean_queries", "min_queries",
        "max_queries",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _chart_points(summary: list[dict[str, object]]) -> list[dict]:
    series = []
    for attack, label in (
        ("posterior_trigram", "Trigram prior"),
        ("ncc_uniform", "NCC uniform"),
        ("sequential_halving", "Sequential Halving"),
    ):
        points = [
            (float(row["mean_queries"]), float(row["success_rate"]))
            for row in summary
            if row["experiment"] == "tier3_main"
            and row["scope"] == "all"
            and row["attack"] == attack
        ]
        if points:
            series.append({"label": label, "points": sorted(points)})
    return series


def _write_chart_data(path: Path, series: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["attack", "mean_queries", "success_rate"])
        for item in series:
            for mean_queries, success_rate in item["points"]:
                writer.writerow([item["label"], f"{mean_queries:.3f}", f"{success_rate:.6f}"])


def _matched_rows(
    summary: list[dict[str, object]], target_error: float
) -> list[dict[str, object]]:
    matched = []
    scopes = [("all", "")] + [("band", band) for band in BANDS]
    for scope, band in scopes:
        for attack in ("posterior_trigram", "ncc_uniform", "sequential_halving"):
            rows = [
                row for row in summary
                if row["experiment"] == "tier3_main"
                and row["scope"] == scope
                and (scope == "all" or row["band"] == band)
                and row["attack"] == attack
            ]
            if not rows:
                continue
            good = [
                row for row in rows
                if float(row["error_rate"]) <= target_error + 1e-12
            ]
            if good:
                chosen = min(good, key=lambda row: float(row["mean_queries"]))
                met_target = 1
            else:
                chosen = min(
                    rows,
                    key=lambda row: (
                        float(row["error_rate"]),
                        float(row["mean_queries"]),
                    ),
                )
                met_target = 0
            matched.append({
                "attack": attack,
                "target_error": target_error,
                "met_target": met_target,
                "band": band,
                "grid": chosen["grid"],
                "n": chosen["n"],
                "success_rate": chosen["success_rate"],
                "error_rate": chosen["error_rate"],
                "mean_queries": chosen["mean_queries"],
            })
    return matched


def _write_matched(path: Path, rows: list[dict[str, object]]) -> None:
    fields = [
        "attack", "target_error", "met_target", "band", "grid", "n",
        "success_rate", "error_rate", "mean_queries",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def run_experiments(config: ExperimentConfig) -> dict[str, object]:
    """Run the full Tier 3 matrix and write raw, summary, matched and chart files."""
    if config.per_band < 1:
        raise ValueError("per_band must be positive")
    if not config.grids:
        raise ValueError("grids must not be empty")
    if any(grid < 1 for grid in config.grids):
        raise ValueError("every grid value must be positive")
    if not 0.0 <= config.target_error <= 1.0:
        raise ValueError("target_error must be between 0 and 1")

    backend = _make_backend(config.backend, config.noise)
    partitions, _counts = read_dataset(config.data)
    train_words = [word for word, _band in partitions["train"]]
    test_words = partitions["test"]

    model = ReversedTrigramPrior(train_words, k=1.0)
    if config.k is None:
        chosen_k, dev_loss = choose_k(partitions["dev"], model)
    else:
        model.set_k(config.k)
        chosen_k, dev_loss = config.k, None
    leak_model = ReversedTrigramPrior(
        [word for word, _band in test_words], k=chosen_k
    )

    rng = random.Random(config.seed)
    sample = _sample_test_words(test_words, config.per_band, rng)
    main_cases = _word_cases(sample, backend.encrypt)
    random_cases = _random_cases(
        len(main_cases), backend.encrypt, random.Random(config.seed + 1)
    )

    methods = [
        ("posterior_trigram", posterior_attack, {"delta": DELTA}),
        ("ncc_uniform", ncc_attack, {"delta": DELTA}),
        ("sequential_halving", sequential_halving_attack, {}),
    ]
    scenarios = [
        ("tier3_main", main_cases, model, "train", methods),
        ("tier3_train_equals_test", main_cases, leak_model, "leak", methods[:1]),
        ("tier3_random_bytes", random_cases, model, "train", methods),
    ]

    rows: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory() as temporary:
        temp_dir = Path(temporary)
        group_index = 0
        for experiment, cases, prior, prior_name, scenario_methods in scenarios:
            for attack_name, attack, params in scenario_methods:
                for grid in config.grids:
                    if attack_name == "sequential_halving" and grid < SH_MIN_QUERIES:
                        continue
                    rows.extend(_run_group(
                        config=config,
                        experiment=experiment,
                        attack_name=attack_name,
                        attack=attack,
                        cases=cases,
                        prior_name=prior_name if attack_name == "posterior_trigram" else "",
                        grid=grid,
                        params=dict(params, **({"prior": prior} if attack_name == "posterior_trigram" else {})),
                        backend=backend,
                        temp_dir=temp_dir,
                        index=group_index,
                    ))
                    group_index += 1

    _write_rows(config.output, rows)
    summary = _summarize(rows)
    _write_summary(config.summary, summary)
    series = _chart_points(summary)
    _write_chart_data(config.chart_data, series)
    matched = _matched_rows(summary, config.target_error)
    _write_matched(config.matched, matched)
    write_line_chart_pdf(
        config.figure,
        series,
        title="Tier 3: success rate against measured queries per word",
        xlabel="Queries per word (measured, log scale)",
    )

    return {
        "k": chosen_k,
        "dev_loss_bits_per_byte": dev_loss,
        "per_band": config.per_band,
        "backend": config.backend,
        "n_rows": len(rows),
        "output": str(config.output),
        "summary": str(config.summary),
        "matched": str(config.matched),
        "figure": str(config.figure),
        "matched_rows": matched,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the T12b Tier 3 experiments.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--data", type=Path, default=Path("data/wordlist/words8.csv"))
    parser.add_argument("--output", type=Path, default=Path("results/tier3_experiments.csv"))
    parser.add_argument("--summary", type=Path, default=Path("results/tier3_summary.csv"))
    parser.add_argument("--chart-data", type=Path, default=Path("results/tier3_chart_data.csv"))
    parser.add_argument("--matched", type=Path, default=Path("results/tier3_matched_error.csv"))
    parser.add_argument("--figure", type=Path, default=Path("figures/tier3_success_vs_queries.pdf"))
    parser.add_argument("--per-band", type=int, default=DEFAULT_PER_BAND)
    parser.add_argument("--grids", default=",".join(str(g) for g in DEFAULT_GRIDS))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--backend", choices=("aes", "fake"), default="aes")
    parser.add_argument("--k", type=float, default=None)
    parser.add_argument("--target-error", type=float, default=0.01)
    parser.add_argument("--noise-off", action="store_true")
    args = parser.parse_args()

    config = ExperimentConfig(
        data=args.data,
        output=args.output,
        summary=args.summary,
        chart_data=args.chart_data,
        matched=args.matched,
        figure=args.figure,
        per_band=args.per_band,
        grids=tuple(int(value) for value in args.grids.split(",") if value),
        seed=args.seed,
        backend=args.backend,
        k=args.k,
        target_error=args.target_error,
        noise=not args.noise_off,
    )
    print(json.dumps(run_experiments(config), indent=2))


if __name__ == "__main__":
    main()
