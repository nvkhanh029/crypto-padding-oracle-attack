"""Dictionary attack for the D15 eight-byte word layout."""

from __future__ import annotations

import csv
import random
from collections.abc import Callable, Iterable
from pathlib import Path

from ..core.contracts import BLOCK_SIZE, AttackFailure, BaseOracle, validate_ciphertext
from ..core.fakes import stub_sequential_check

SequentialCheck = Callable[..., bool]


def _load_dictionary(seed: int) -> list[bytes]:
    wordlist = Path(__file__).parents[3] / "data" / "wordlist" / "words8.csv"
    with wordlist.open(encoding="utf-8", newline="") as source:
        words = [row["word"].encode("ascii") for row in csv.DictReader(source)]
    random.Random(seed).shuffle(words)
    return words


def attack(oracle: BaseOracle, ciphertext: bytes, n_bytes: int = 8,
           **params: object) -> bytes:
    """Try SCOWL word candidates using the supplied sequential padding test.

    The default checker is the T0a one-sample stub. Replace it with T7's
    sequential checker for experiments.
    """
    validate_ciphertext(ciphertext)
    if len(ciphertext) != 2 * BLOCK_SIZE:
        raise ValueError("dictionary attack requires exactly two ciphertext blocks")
    if n_bytes != 8:
        raise ValueError("the D15 dictionary attack recovers exactly 8 word bytes")

    checker = params.pop("sequential_check", stub_sequential_check)
    candidates = params.pop("dictionary", None)
    seed = params.pop("seed", 42)
    if params:
        unexpected = ", ".join(sorted(params))
        raise TypeError(f"unexpected attack parameter(s): {unexpected}")
    if not callable(checker):
        raise TypeError("sequential_check must be callable")
    if not isinstance(seed, int):
        raise TypeError("seed must be an integer")
    words: Iterable[bytes] = _load_dictionary(seed) if candidates is None else candidates

    original_previous = ciphertext[:BLOCK_SIZE]
    target_block = ciphertext[BLOCK_SIZE:]
    for candidate in words:
        candidate_bytes = (
            candidate.encode("ascii") if isinstance(candidate, str) else candidate
        )
        if not isinstance(candidate_bytes, bytes) or len(candidate_bytes) != n_bytes:
            raise ValueError("every dictionary candidate must contain exactly 8 ASCII bytes")
        if (
            not candidate_bytes.isascii()
            or not candidate_bytes.isalpha()
            or not candidate_bytes.islower()
        ):
            raise ValueError("dictionary candidates must be lowercase ASCII words")

        crafted_previous = bytearray(original_previous)
        for index, value in enumerate(candidate_bytes, start=BLOCK_SIZE - n_bytes):
            crafted_previous[index] ^= value ^ n_bytes

        if not checker(oracle, bytes(crafted_previous) + target_block):
            continue

        verification_previous = bytearray(crafted_previous)
        verification_previous[BLOCK_SIZE - n_bytes] ^= 1
        if not checker(oracle, bytes(verification_previous) + target_block):
            return candidate_bytes

    raise AttackFailure("no dictionary candidate matched the target block")
