"""T8a: dictionary attack for the D15 word layout.

Instead of trying all 256 byte values per position (the random-block
baseline), we only try letters that keep the guess a possible word from the
SCOWL eight-letter list (D11) — narrowing candidates with the letters T7's
sequential_attack has already recovered to the right.
"""

from __future__ import annotations
import csv
from pathlib import Path

from .sequential import sequential_attack

DEFAULT_WORDLIST_PATH = Path(__file__).parents[3] / "data" / "wordlist" / "words8.csv"


def load_words(path: Path | str = DEFAULT_WORDLIST_PATH) -> list[str]:
    with open(path, encoding="utf-8", newline="") as source:
        return [row["word"] for row in csv.DictReader(source)]

def make_candidate_order(words: list[str]):
    """Create a candidate_order hook for sequential_attack, based on `words`."""

    def candidate_order(position: int, suffix: bytes):
        k = len(suffix)                              
        tail = suffix.decode("ascii", errors="replace")

        seen: set[int] = set()
        order: list[int] = []
        for word in words:
            if k > 0 and word[8 - k:] != tail:
                continue                             
            value = ord(word[7 - k]) 
            if value not in seen:                 
                seen.add(value)
                order.append(value)

        if not order:
            order = [ord(c) for c in "abcdefghijklmnopqrstuvwxyz"]
        return order

    return candidate_order

def dictionary_attack(oracle, ciphertext: bytes, n_bytes: int, **params) -> bytes:
    """T8a: dictionary attack on D15 layout, using the candidate_order above."""
    words = params.pop("words", None)
    if words is None:
        words = load_words()
    order_fn = make_candidate_order(words)
    return sequential_attack(
        oracle, ciphertext, n_bytes, candidate_order=order_fn, **params
    )