"""T7: Canvel-style ordered sequential test for the noisy oracle.

Canvel et al. (2003) do not decide a padding question from one timing sample:
they take samples until the accumulated evidence for "padding right" (mean
mu_r) against "padding wrong" (mean mu_w) is strong enough, then accept or
reject. This module implements that test (their `Check4`) and the ordered
byte loop around it (`DecryptByte4`/`DecryptBlock4`).

The noise model is Gaussian with the same sigma for both cases, as Canvel
Conjecture 1 assumes:

    LLR_j = sum_i (mu_r - mu_w) * (T_i - (mu_r + mu_w) / 2) / sigma**2

`LLR_j` is the log-likelihood ratio for "padding right" after j samples. It
starts at 0. We query again while `tau_lo < LLR_j < tau_hi`; when it reaches
`tau_hi` we accept (True), and when it reaches `tau_lo` we reject (False).
Eq. (1)-(2) in Canvel is the STOP/ACCEPT rule on their sum S_j; the thresholds
`tau_lo` and `tau_hi` are the Wald thresholds described in Sec. 2.3
(unnumbered). `wald_thresholds` builds them for chosen error rates, and
`canvel_thresholds` builds them from Canvel Eq. (6)-(7) for a target success
probability.

As in Canvel, the same thresholds are used for every candidate. At the last
byte (position 15) an ACCEPT is confirmed once by flipping the previous byte
of the forged block: this rejects the false 02 02 padding that a wrong
candidate can create. If no candidate is accepted, the list is tried again,
up to 3 rounds; after that the candidate with the highest LLR is used so the
attack still returns n_bytes bytes for the harness to check.

Block layout (D15): the ciphertext is exactly two blocks, the previous block
(the IV or a ciphertext block) followed by the target block. Bytes are
recovered from the end of the target block towards the front; `n_bytes=8`
recovers the eight-letter word in block bytes 9-16 and stops there.

Python 3.11+.
"""

from __future__ import annotations

import math
from typing import Callable, Iterable

from ..core.contracts import BLOCK_SIZE, BaseOracle, validate_ciphertext
from .noisy_oracle import MU_R, MU_W, SIGMA

# A candidate order: position is the absolute block index (0-15) and suffix is
# the already recovered plaintext to its right. It yields candidate bytes.
CandidateOrder = Callable[[int, bytes], Iterable[int]]


def wald_thresholds(
    epsilon_plus: float, epsilon_minus: float
) -> tuple[float, float]:
    """Return (tau_lo, tau_hi) for the sequential test, in log-odds units.

    `epsilon_plus` is the false-accept rate: accepting a wrong candidate as
    "padding right". `epsilon_minus` is the false-reject rate: rejecting the
    right candidate. Wald's thresholds give

        log tau+ = log((1 - epsilon_minus) / epsilon_plus)
        log tau- = log(epsilon_minus / (1 - epsilon_plus))

    These are the Wald thresholds discussed in Canvel Sec. 2.3
    (unnumbered); Canvel Eq. (1)-(2) is the STOP/ACCEPT rule on S_j, not
    this formula. The bounds must be in (0, 1) and their sum below 1, so
    that tau_lo < 0 < tau_hi.
    """
    for name, value in (
        ("epsilon_plus", epsilon_plus),
        ("epsilon_minus", epsilon_minus),
    ):
        if not 0.0 < value < 1.0:
            raise ValueError(f"{name} must be between 0 and 1")
    if epsilon_plus + epsilon_minus >= 1.0:
        raise ValueError("epsilon_plus + epsilon_minus must be below 1")

    tau_hi = math.log((1.0 - epsilon_minus) / epsilon_plus)
    tau_lo = math.log(epsilon_minus / (1.0 - epsilon_plus))
    return tau_lo, tau_hi


def canvel_thresholds(
    c0: float, b: int, p: float = 0.5
) -> tuple[float, float]:
    """Return Canvel's (log tau_lo, log tau_hi) for a target success p.

    This uses Canvel Eq. (6)-(7) with natural logs (the formulas are also
    in docs/canvel-fact-check.md, section 3):

        log tau+ = ln C0 + ln(C0 - b) - ln b - ln ln(1/p)
        log tau- = ln(C0 - b) - ln C0 - ln b + ln ln(1/p)

    C0 is the average number of candidate trials per block and b is the
    number of bytes. `random_block_c0(b)` gives C0 for uniform random
    bytes; `dictionary_c0(words, candidate_order)` gives it for a word list.
    """
    if not isinstance(b, int) or b < 1:
        raise ValueError("b must be a positive integer")
    if not c0 > b:
        raise ValueError("c0 must be greater than b")
    if not 0.0 < p < 1.0:
        raise ValueError("p must be between 0 and 1")

    log_log = math.log(math.log(1.0 / p))
    log_tau_hi = math.log(c0) + math.log(c0 - b) - math.log(b) - log_log
    log_tau_lo = math.log(c0 - b) - math.log(c0) - math.log(b) + log_log
    return log_tau_lo, log_tau_hi


def random_block_c0(b: int) -> float:
    """C0 for a uniform random block of b bytes: b(|Z| - 1)/2 + b."""
    if not isinstance(b, int) or b < 1:
        raise ValueError("b must be a positive integer")
    return b * (256 - 1) / 2.0 + b


def dictionary_c0(words: Iterable[str]) -> float:
    """C0 for an 8-letter word list using T8a's candidate order.

    T8a orders candidates by scanning the word list and keeping the unique
    next letters for the already known suffix. We build that same order once
    per suffix, then for each word add 1 + the position of its true byte in
    the order, summed over the 8 bytes, and average over the words.
    """
    word_list = list(words)
    if not word_list:
        raise ValueError("words must not be empty")
    for word in word_list:
        if len(word) != 8:
            raise ValueError(f"word {word!r} must have 8 characters")

    # suffix (0..7 letters) -> candidate bytes in T8a's word-list order.
    by_suffix: dict[str, list[int]] = {}
    for word in word_list:
        for k in range(8):
            suffix = word[8 - k:] if k else ""
            value = ord(word[7 - k])
            order = by_suffix.setdefault(suffix, [])
            if value not in order:
                order.append(value)

    total = 0
    for word in word_list:
        for position in range(15, 7, -1):
            k = 15 - position
            suffix = word[8 - k:] if k else ""
            target = ord(word[position - 8])
            order = by_suffix[suffix]
            if target not in order:
                raise ValueError(
                    f"candidate order has no candidate for {word!r} "
                    f"at position {position}"
                )
            total += order.index(target) + 1
    return total / len(word_list)


def sequential_check(
    oracle: BaseOracle,
    ciphertext: bytes,
    *,
    tau_lo: float,
    tau_hi: float,
    mu_r: float = MU_R,
    mu_w: float = MU_W,
    sigma: float = SIGMA,
    max_samples: int | None = None,
) -> bool:
    """Decide one padding question from repeated timing samples.

    Returns True if the padding is judged right, False if it is judged wrong.
    The thresholds are the log-odds bounds from `wald_thresholds`; they do not
    depend on the candidate, as in Canvel's `Check4` (T2 fact S5).

    `max_samples` is an optional hard budget. If it is reached before a bound,
    the test returns the current best answer (LLR > 0). Without it, the test
    keeps sampling until a bound is crossed.

    Queries are counted only by the oracle; this function keeps no counter.
    A malformed ciphertext is rejected by the oracle and not counted.
    """
    _require_two_blocks(ciphertext)
    _check_test_params(tau_lo, tau_hi, mu_r, mu_w, sigma, max_samples)
    accepted, _ = _run_sequential(
        oracle, ciphertext, tau_lo, tau_hi, mu_r, mu_w, sigma, max_samples
    )
    return accepted


def sequential_attack(
    oracle: BaseOracle,
    ciphertext: bytes,
    n_bytes: int,
    *,
    tau_lo: float,
    tau_hi: float,
    mu_r: float = MU_R,
    mu_w: float = MU_W,
    sigma: float = SIGMA,
    candidate_order: CandidateOrder | None = None,
    max_samples: int | None = None,
) -> bytes:
    """Recover `n_bytes` from the end of the target block, in order.

    This is Canvel's `DecryptBlock4` loop with the sequential test above. For
    each byte, candidates are tried in the order given by `candidate_order`;
    the first accepted value is kept and the padding for the next byte is
    updated. With `candidate_order=None`, candidates are tried as 0..255
    (uniform order, the random-block baseline for T8b).

    At position 15 an ACCEPT is confirmed once with `sequential_check`, after
    flipping byte 14 of the forged block. This rejects the false 02 02
    padding a wrong last-byte guess can create. When no candidate is
    accepted, the whole list is tried again, up to 3 rounds; after that the
    highest-LLR candidate is kept (and the harness checks success).

    `candidate_order(position, suffix)` receives the absolute block index
    (15 down to 16 - n_bytes) and the recovered bytes to its right. T8a uses
    this hook to order candidates by the word list.

    Returns exactly `n_bytes` recovered bytes, in plaintext order. The caller
    (the harness) checks success; this function does not.
    """
    _require_two_blocks(ciphertext)
    if not isinstance(n_bytes, int) or not 1 <= n_bytes <= BLOCK_SIZE:
        raise ValueError(f"n_bytes must be between 1 and {BLOCK_SIZE}")
    _check_test_params(tau_lo, tau_hi, mu_r, mu_w, sigma, max_samples)
    if candidate_order is not None and not callable(candidate_order):
        raise TypeError("candidate_order must be callable")

    previous = ciphertext[:BLOCK_SIZE]
    target = ciphertext[BLOCK_SIZE:]
    plain = bytearray(BLOCK_SIZE)

    for position in range(BLOCK_SIZE - 1, BLOCK_SIZE - n_bytes - 1, -1):
        pad = BLOCK_SIZE - position
        forged = bytearray(previous)
        # Force the already known bytes to the padding value the oracle needs.
        for j in range(position + 1, BLOCK_SIZE):
            forged[j] = previous[j] ^ plain[j] ^ pad

        suffix = bytes(plain[position + 1:])
        if candidate_order is None:
            candidates = list(range(256))
        else:
            candidates = list(candidate_order(position, suffix))
        if not candidates:
            raise ValueError("candidate_order yielded no candidates")
        for value in candidates:
            if not isinstance(value, int) or not 0 <= value <= 255:
                raise ValueError("candidate bytes must be integers 0..255")

        best_value: int | None = None
        best_llr = -math.inf
        accepted_value: int | None = None

        # Canvel's DecryptByte4 tests the whole candidate list again when no
        # candidate is accepted. Three rounds are enough in our runs.
        for _round in range(3):
            for value in candidates:
                forged[position] = previous[position] ^ value ^ pad
                accepted, log_lr = _run_sequential(
                    oracle,
                    bytes(forged) + target,
                    tau_lo,
                    tau_hi,
                    mu_r,
                    mu_w,
                    sigma,
                    max_samples,
                )
                if accepted:
                    if position == BLOCK_SIZE - 1:
                        # A wrong guess can make the last byte 0x02 and turn
                        # the original plaintext 0x02 0x02 into valid padding.
                        # Flip byte 14: a true 0x01 padding stays valid, the
                        # false 0x02 0x02 padding does not.
                        forged[position - 1] ^= 0x01
                        confirmed = sequential_check(
                            oracle,
                            bytes(forged) + target,
                            tau_lo=tau_lo,
                            tau_hi=tau_hi,
                            mu_r=mu_r,
                            mu_w=mu_w,
                            sigma=sigma,
                            max_samples=max_samples,
                        )
                        forged[position - 1] ^= 0x01
                        if not confirmed:
                            continue
                    accepted_value = value
                    break
                if log_lr > best_llr:
                    best_llr = log_lr
                    best_value = value
            if accepted_value is not None:
                break

        if accepted_value is not None:
            plain[position] = accepted_value
        else:
            # No candidate passed after 3 rounds. Canvel has no backtracking;
            # keep the highest-LLR candidate so the attack still returns a
            # full result for the harness to check.
            if best_value is None:
                raise ValueError("candidate_order yielded no candidates")
            plain[position] = best_value

    return bytes(plain[BLOCK_SIZE - n_bytes:])


def _run_sequential(
    oracle: BaseOracle,
    ciphertext: bytes,
    tau_lo: float,
    tau_hi: float,
    mu_r: float,
    mu_w: float,
    sigma: float,
    max_samples: int | None,
) -> tuple[bool, float]:
    """Run the log-likelihood test and return (decision, final LLR)."""
    log_lr = 0.0
    samples = 0
    while max_samples is None or samples < max_samples:
        sample = oracle.query(ciphertext)
        log_lr += (mu_r - mu_w) * (sample - (mu_r + mu_w) / 2.0) / (sigma * sigma)
        samples += 1
        if log_lr >= tau_hi:
            return True, log_lr
        if log_lr <= tau_lo:
            return False, log_lr
    return log_lr > 0.0, log_lr


def _require_two_blocks(ciphertext: bytes) -> None:
    validate_ciphertext(ciphertext)
    if len(ciphertext) != 2 * BLOCK_SIZE:
        raise ValueError(
            "the sequential test expects exactly two blocks "
            f"({2 * BLOCK_SIZE} bytes), got {len(ciphertext)}"
        )


def _check_test_params(
    tau_lo: float,
    tau_hi: float,
    mu_r: float,
    mu_w: float,
    sigma: float,
    max_samples: int | None,
) -> None:
    if not tau_lo < 0.0 < tau_hi:
        raise ValueError("need tau_lo < 0 < tau_hi (log-odds bounds)")
    if mu_r == mu_w:
        raise ValueError("mu_r and mu_w must differ")
    if sigma <= 0.0:
        raise ValueError("sigma must be positive")
    if max_samples is not None and (
        not isinstance(max_samples, int) or max_samples < 1
    ):
        raise ValueError("max_samples must be a positive integer or None")
