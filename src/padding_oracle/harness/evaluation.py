"""Run attacks over target cases and write the shared CSV results format."""

from __future__ import annotations

import csv
import logging
from collections.abc import Iterable, Mapping, Sized
from dataclasses import dataclass
from pathlib import Path

from ..core.contracts import (
    CSV_COLUMNS,
    Attack,
    AttackFailure,
    BaseOracle,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ExperimentCase:
    target: str
    ciphertext: bytes
    expected: bytes
    band: str = ""


def _format_params(params: Mapping[str, object]) -> str:
    parts = []
    for key, value in sorted(params.items()):
        if callable(value):
            formatted = getattr(value, "__name__", type(value).__name__)
        elif key == "dictionary":
            formatted = (
                f"{len(value)} candidates" if isinstance(value, Sized) else "configured"
            )
        else:
            formatted = str(value)
        parts.append(f"{key}={formatted}")
    return ";".join(parts)


def run_experiment(
    *,
    experiment: str,
    attack_name: str,
    oracle: BaseOracle,
    attack: Attack,
    cases: Iterable[ExperimentCase],
    seed: int,
    output_path: Path,
    n_bytes: int,
    attack_params: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    """Run one attack per case and persist rows using ``CSV_COLUMNS``."""
    cases = list(cases)
    if not cases:
        raise ValueError("an experiment must contain at least one target case")
    if n_bytes < 1:
        raise ValueError("n_bytes must be positive")

    params = {} if attack_params is None else dict(attack_params)
    params_text = _format_params(params)
    rows: list[dict[str, object]] = []
    for case in cases:
        if len(case.expected) != n_bytes:
            raise ValueError(
                f"target {case.target!r}: expected truth must contain {n_bytes} bytes"
            )
        oracle.reset()
        try:
            recovered = attack(oracle, case.ciphertext, n_bytes, **params)
            if not isinstance(recovered, bytes):
                raise TypeError(f"{attack_name} must return bytes")
            if len(recovered) != n_bytes:
                raise ValueError(
                    f"{attack_name} returned {len(recovered)} bytes; expected {n_bytes}"
                )
            success = int(recovered == case.expected)
        except AttackFailure as error:
            logger.warning(
                "%s failed for %s against %s after %d queries: %s",
                attack_name, case.target, type(oracle).__name__, oracle.queries, error,
            )
            success = 0

        rows.append({
            "experiment": experiment,
            "attack": attack_name,
            "oracle": type(oracle).__name__,
            "seed": seed,
            "target": case.target,
            "band": case.band,
            "bytes_attacked": n_bytes,
            "queries": oracle.queries,
            "success": success,
            "params": params_text,
        })

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=CSV_COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    return rows


def run_tier1_experiment(
    *,
    experiment: str,
    attack_name: str,
    oracle: BaseOracle,
    cases: Iterable[ExperimentCase],
    seed: int,
    output_path: Path,
    n_bytes: int,
    attack_params: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    """Run Vaudenay's Tier 1 attack through the shared evaluator."""
    from ..tier1.vaudenay import attack

    return run_experiment(
        experiment=experiment,
        attack_name=attack_name,
        oracle=oracle,
        attack=attack,
        cases=cases,
        seed=seed,
        output_path=output_path,
        n_bytes=n_bytes,
        attack_params=attack_params,
    )


def run_tier2_experiment(
    *,
    experiment: str,
    attack_name: str,
    oracle: BaseOracle,
    cases: Iterable[ExperimentCase],
    seed: int,
    output_path: Path,
    n_bytes: int,
    attack_params: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    """Run the Tier 2 dictionary attack through the shared evaluator."""
    from ..tier2.dictionary import attack

    params = {} if attack_params is None else dict(attack_params)
    params.setdefault("seed", seed)
    return run_experiment(
        experiment=experiment,
        attack_name=attack_name,
        oracle=oracle,
        attack=attack,
        cases=cases,
        seed=seed,
        output_path=output_path,
        n_bytes=n_bytes,
        attack_params=params,
    )
