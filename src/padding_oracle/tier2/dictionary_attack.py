"""T8a: dictionary attack for the D15 word layout.

The random-block baseline tries all 256 byte values for every byte. Here we
try only the letters that keep the guess a possible word of the SCOWL
eight-letter list (D11), given the letters already recovered to the right.
The byte loop and the sequential test are T7's `sequential_attack`; this
module only gives it the candidate order.

Candidate order: the word list is scanned in file order (sorted by word), and
each new next letter is added when it first appears, so candidates come out
in alphabetical order. This is the order `dictionary_c0` (T7) assumes. It is
NOT Canvel's order (Sec. 4.2 sorts candidates by decreasing probability).

Limit: a word that is not in the list cannot be recovered. The attack then
returns some other bytes without any error; the harness sees `success = 0`.
"""

from __future__ import annotations

import csv
from pathlib import Path

from .sequential import sequential_attack

DEFAULT_WORDLIST_PATH = Path(__file__).parents[3] / "data" / "wordlist" / "words8.csv"

WORD_LENGTH = 8
LETTERS = [ord(c) for c in "abcdefghijklmnopqrstuvwxyz"]

# The settings `sequential_attack` (T7) understands. Other settings in
# `params` (for example a seed the harness writes to the CSV) are ignored.
_SEQUENTIAL_SETTINGS = ("tau_lo", "tau_hi", "mu_r", "mu_w", "sigma", "max_samples")


def load_words(path: Path | str = DEFAULT_WORDLIST_PATH) -> list[str]:
    """Read the `word` column of the word-list CSV (all bands, all splits)."""
    with open(path, encoding="utf-8", newline="") as source:
        return [row["word"] for row in csv.DictReader(source)]


def make_candidate_order(words: list[str]):
    """Create a `candidate_order` hook for `sequential_attack` from `words`.

    The hook receives the bytes already recovered to the right (`suffix`) and
    returns the byte values to try, in order:
      - inside the word: the next letters of every word that ends with
        `suffix`, in the order they first appear in `words`;
      - if no word ends with `suffix` (an earlier byte was wrong, or the word
        is not in the list): the letters a-z;
      - left of the word (`suffix` already has 8 letters): all 256 values,
        because those bytes are not part of the word.
    """
    for word in words:
        if len(word) != WORD_LENGTH:
            raise ValueError(f"word {word!r} must have {WORD_LENGTH} letters")

    def candidate_order(position: int, suffix: bytes) -> list[int]:
        k = len(suffix)                      # letters already known
        if k >= WORD_LENGTH:
            return list(range(256))
        tail = suffix.decode("ascii", errors="replace")

        seen: set[int] = set()
        order: list[int] = []
        for word in words:
            if k > 0 and word[WORD_LENGTH - k:] != tail:
                continue
            value = ord(word[WORD_LENGTH - 1 - k])
            if value not in seen:
                seen.add(value)
                order.append(value)

        if not order:
            return list(LETTERS)
        return order

    return candidate_order


def dictionary_attack(oracle, ciphertext: bytes, n_bytes: int, **params) -> bytes:
    """T8a: dictionary attack on the D15 layout (the `Attack` shape).

    oracle:     a noisy timing oracle (passed in, never created here).
    ciphertext: exactly two blocks: previous block (or IV) + target block.
    n_bytes:    8 for the word in block bytes 9-16.
    params:     `tau_lo` and `tau_hi` are required (see `wald_thresholds` and
                `canvel_thresholds`); `mu_r`, `mu_w`, `sigma`, `max_samples`
                are passed on to `sequential_attack`; `words` is the word
                list (default: the SCOWL list in data/wordlist). Other
                settings are accepted and ignored.

    There is no query budget for the whole word here, so `max_queries` is
    refused: ignoring it would let a run look as if it had a budget.
    """
    if "max_queries" in params:
        raise ValueError(
            "dictionary_attack has no whole-word query budget; "
            "max_queries is not supported (max_samples limits one test)"
        )
    words = params.get("words")
    if words is None:
        words = load_words()
    settings = {name: params[name] for name in _SEQUENTIAL_SETTINGS if name in params}
    return sequential_attack(
        oracle,
        ciphertext,
        n_bytes,
        candidate_order=make_candidate_order(words),
        **settings,
    )
