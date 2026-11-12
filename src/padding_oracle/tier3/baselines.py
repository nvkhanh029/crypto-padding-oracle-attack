"""T11: the two Tier 3 baselines.

Baseline (c), NCC 2023: the T10 posterior-threshold attack with a uniform
prior. It is the same decision rule on the same Gaussian timing noise; only
the prior differs, which isolates the effect of the T9 trigram prior.

Sequential Halving (Karnin, Koren and Somekh, 2013): split the 256 candidate
bytes round by round, query every remaining candidate a number of times from
the query budget, keep the half with the highest mean timing (padding right
takes longer: MU_R > MU_W), and accept the last survivor. It uses no prior
and no probability threshold.

Both baselines take the query budget as an input. T12b compares the methods
at the same measured error rate and on the same query-budget grid.

Python 3.11+.
"""

from __future__ import annotations

import math
import random

from ..core.contracts import BLOCK_SIZE, BaseOracle
from .posterior_attack import (
    DELTA,
    MU_R,
    MU_W,
    SIGMA,
    posterior_attack,
    uniform_prior,
)

# 256 possible byte values, and the number of halving rounds for them.
N_CANDIDATES = 256
SH_ROUNDS = math.ceil(math.log2(N_CANDIDATES))


def ncc_attack(
    oracle: BaseOracle,
    ciphertext: bytes,
    n_bytes: int,
    delta: float = DELTA,
    mu_r: float = MU_R,
    mu_w: float = MU_W,
    sigma: float = SIGMA,
    max_queries: int | None = None,
    seed: int = 0,
    **params,
) -> bytes:
    """Baseline (c): the T10 attack with a uniform prior (NCC 2023).

    This is deliberately a thin wrapper: no new decision rule. It exists so
    the experiments can name the baseline and so a reader can see that the
    only difference from our attack is the prior.

    Parameters are the same as `posterior_attack`; extra `params` (for
    example k for the CSV) are accepted and ignored.
    """
    return posterior_attack(
        oracle,
        ciphertext,
        n_bytes,
        prior=uniform_prior,
        delta=delta,
        mu_r=mu_r,
        mu_w=mu_w,
        sigma=sigma,
        max_queries=max_queries,
        seed=seed,
        **params,
    )


def sequential_halving_byte(
    oracle: BaseOracle,
    prev: bytes,
    target: bytes,
    position: int,
    known: dict[int, int],
    budget: int,
    rng: random.Random,
) -> int:
    """Recover one byte with Sequential Halving (Karnin et al. 2013).

    `budget` is the query budget for this byte. In each of the
    `SH_ROUNDS` rounds, every remaining candidate is queried
    `budget // (|S| * SH_ROUNDS)` times; the half with the highest mean
    timing survives. After the last round one candidate is left.

    The forged block uses fresh random bytes to the left of `position`, as
    in the T10 attack: a wrong guess cannot keep a shorter padding valid by
    accident.
    """
    if len(prev) != BLOCK_SIZE or len(target) != BLOCK_SIZE:
        raise ValueError("prev and target must be 16 bytes each")
    if not 0 <= position < BLOCK_SIZE:
        raise ValueError("position must be between 0 and 15")
    if not isinstance(budget, int) or budget < N_CANDIDATES * SH_ROUNDS:
        raise ValueError(
            "budget must be an integer of at least "
            f"{N_CANDIDATES * SH_ROUNDS} queries per byte"
        )

    candidates = list(range(N_CANDIDATES))
    pad = BLOCK_SIZE - position

    for _ in range(SH_ROUNDS):
        samples_each = budget // (len(candidates) * SH_ROUNDS)
        scores = []
        for guess in candidates:
            total = 0.0
            for _ in range(samples_each):
                total += oracle.query(
                    _forge_block(prev, target, position, guess, known, pad, rng)
                )
            scores.append(total / samples_each)

        # Padding right takes longer, so keep the highest means.
        order = sorted(range(len(candidates)), key=lambda i: scores[i],
                       reverse=True)
        keep = max(1, len(candidates) // 2)
        candidates = [candidates[i] for i in order[:keep]]

    return candidates[0]


def sequential_halving_attack(
    oracle: BaseOracle,
    ciphertext: bytes,
    n_bytes: int,
    *,
    budget_per_byte: int,
    seed: int = 0,
    **params,
) -> bytes:
    """Sequential Halving baseline for `n_bytes` bytes (the Attack shape).

    `budget_per_byte` is the B from the T11 spec, applied to each byte in
    turn. The attack recovers bytes from the end of the target block, so
    `n_bytes=8` is the D15 word layout. No prior and no timing model are
    used: only the ordering of the sample means matters.

    Extra `params` are accepted and ignored, so the experiment harness can
    pass the same settings text to every method.
    """
    if len(ciphertext) != 2 * BLOCK_SIZE:
        raise ValueError("ciphertext must be exactly two blocks (32 bytes)")
    if not isinstance(n_bytes, int) or not 1 <= n_bytes <= BLOCK_SIZE:
        raise ValueError(f"n_bytes must be between 1 and {BLOCK_SIZE}")
    if not isinstance(budget_per_byte, int) or budget_per_byte < (
        N_CANDIDATES * SH_ROUNDS
    ):
        raise ValueError(
            "budget_per_byte must be an integer of at least "
            f"{N_CANDIDATES * SH_ROUNDS}"
        )

    prev = ciphertext[:BLOCK_SIZE]
    target = ciphertext[BLOCK_SIZE:]
    rng = random.Random(seed)
    known: dict[int, int] = {}

    for position in range(BLOCK_SIZE - 1, BLOCK_SIZE - 1 - n_bytes, -1):
        known[position] = sequential_halving_byte(
            oracle, prev, target, position, known, budget_per_byte, rng
        )

    return bytes(known[j] for j in range(BLOCK_SIZE - n_bytes, BLOCK_SIZE))


def _forge_block(
    prev: bytes,
    target: bytes,
    position: int,
    guess: int,
    known: dict[int, int],
    pad: int,
    rng: random.Random,
) -> bytes:
    """Build the two-block ciphertext that tests `guess` for `position`.

    Same construction as the T10 attack: random bytes to the left of the
    tested byte, the padding value v at the tested byte when the guess is
    right, and the known bytes to the right forced to v as well.
    """
    forged = bytearray(rng.randbytes(position))
    forged.append(prev[position] ^ guess ^ pad)
    for j in range(position + 1, BLOCK_SIZE):
        forged.append(prev[j] ^ known[j] ^ pad)
    return bytes(forged) + target
