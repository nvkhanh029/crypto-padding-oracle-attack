"""Shared contracts for the padding-oracle project (T0a).

This file holds the EXACT rules every module uses: the oracle classes and
query counter, along with the result (CSV) columns. Code and tests import from
here, so a wrong name fails straight away.

The reasons behind these rules, and how to use the fake oracles, are in
docs/contracts.md. If that document and this file ever disagree, THIS FILE
(the code) is right.

Guide for the team
------------------
- Build and test your module against the FAKE oracles in `fakes.py`.
- An attack never makes its own oracle: it RECEIVES one as a parameter, so the
  same attack can run against the fake oracle, the real oracle (T3b, T6), and
  future countermeasure adapters without changing its interface.
- When the real oracle is merged, use it for the experiments. The smoke tests
  keep using the fake one (it is fast and needs no AES library).
- Every query goes through `oracle.query(...)`, which counts it exactly once.
  Never count queries yourself.

Python 3.11+.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

# --- Sizes -----------------------------------------------------------------

BLOCK_SIZE = 16  # AES block size, in bytes.

# --- Result file (one CSV per experiment, in results/) ---------------------
# One row = one attack on one target (one random block, or one test word).
# Rates and the Tier 1 confidence interval are computed from the rows, so the
# raw rows must be kept. Comma separated, UTF-8, exactly this header, in order.
CSV_COLUMNS = [
    "experiment",     # groups rows, e.g. "tier1_reproduction"
    "attack",         # which attack, e.g. "vaudenay", "canvel_sequential"
    "oracle",         # oracle class name, e.g. "FakePerfectOracle", "PerfectOracle"
    "seed",           # integer; lets the run be repeated
    "target",         # the target, e.g. "random_block_017" or the secret word
    "band",           # "A".."D" for a word, empty string for a random block
    "bytes_attacked", # how many bytes were recovered: 16 (Tier 1) or 8 (D15)
    "queries",        # oracle.queries after the attack; the main cost number
    "success",        # 1 if every attacked byte was correct, else 0
    "params",         # settings as text, e.g. "delta=0.01;k=0.1" (may be empty)
]

# --- Word-list file contract ----------------------------------------------
# The artifact may be omitted from this branch, but downstream tasks share
# this row schema.
WORDLIST_COLUMNS = ["word", "band", "split"]
BANDS = ["A", "B", "C", "D"]
SPLITS = ["train", "dev", "test"]


# --- Oracle interface ------------------------------------------------------

def validate_ciphertext(ciphertext: bytes) -> None:
    """Reject a ciphertext that is not IV + whole blocks.

    A ciphertext is the IV followed by one or more 16-byte blocks, so its
    length is a multiple of 16 and at least 32 (IV + one target block).
    """
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext must be bytes")
    n = len(ciphertext)
    if n < 2 * BLOCK_SIZE or n % BLOCK_SIZE != 0:
        raise ValueError(
            f"ciphertext length {n} must be a multiple of {BLOCK_SIZE} "
            f"and at least {2 * BLOCK_SIZE} (IV + at least one block)"
        )


class BaseOracle:
    """Common base for every oracle. It owns the query counter.

    A real oracle (T3b perfect, T6 noisy) or a fake one subclasses this and
    implements `_answer`. It must NOT touch `self.queries` or override
    `query`: the counter is handled here, once per call, so no attack can
    forget to count and no one can count twice (see decision D14).
    """

    def __init__(self) -> None:
        self.queries = 0

    def reset(self) -> None:
        """Set the query counter back to 0 (call before each attack run)."""
        self.queries = 0

    def query(self, ciphertext: bytes):
        """Count one query and return the oracle's answer."""
        validate_ciphertext(ciphertext)
        self.queries += 1
        return self._answer(ciphertext)

    def _answer(self, ciphertext: bytes):
        raise NotImplementedError


class AttackFailure(RuntimeError):
    """The attack cannot recover its target from the observations it received."""


class PerfectOracle(BaseOracle):
    """Server type 1: tells the truth. `query` returns a bool.

    True  = the padding of the decrypted ciphertext is valid.
    False = the padding is invalid.
    """

    def query(self, ciphertext: bytes) -> bool:
        return super().query(ciphertext)

    def _answer(self, ciphertext: bytes) -> bool:
        raise NotImplementedError


class NoisyOracle(BaseOracle):
    """Server type 2: leaks only timing. `query` returns a float.

    The float is ONE timing sample, in time units (the real unit is confirmed
    by T2 against Canvel). Valid padding tends to take longer than invalid.
    The oracle NEVER reveals the true yes/no: the attacker must decide from
    repeated samples (that is the whole point of Tiers 2 and 3).
    """

    def query(self, ciphertext: bytes) -> float:
        return super().query(ciphertext)

    def _answer(self, ciphertext: bytes) -> float:
        raise NotImplementedError


# --- Function shapes the attacks must have ---------------------------------
# These are Protocols: they describe the shape, they are not the code. The
# real attacks (T4, T7, T8a, T10, T11) and the stubs match them.

@runtime_checkable
class Attack(Protocol):
    """Every attack has this shape.

    oracle:     a PerfectOracle or a NoisyOracle (passed in, never created).
    ciphertext: exactly two blocks (32 bytes) = previous block (or IV) +
                the target block. All experiments attack one block at a time.
    n_bytes:    how many bytes to recover, counted from the END of the block:
                16 for Tier 1, 8 for the D15 word layout.
    params:     attack settings (e.g. delta, k); also written to the CSV.
    returns:    the recovered bytes (length n_bytes). The harness compares
                them with the truth for `success` and reads `oracle.queries`.
    """

    def __call__(
        self, oracle: BaseOracle, ciphertext: bytes, n_bytes: int, **params
    ) -> bytes: ...


@runtime_checkable
class SequentialCheck(Protocol):
    """The Canvel-style test T7 provides and T8a calls.

    Asks the noisy oracle about the SAME ciphertext again and again until it is
    confident, then answers one padding question.

    oracle:     a NoisyOracle.
    ciphertext: two blocks (32 bytes), as above.
    params:     the decision thresholds (e.g. tau_lo, tau_hi) chosen by T7.
    returns:    True if the padding is judged valid, else False.
    """

    def __call__(self, oracle: BaseOracle, ciphertext: bytes, **params) -> bool: ...
