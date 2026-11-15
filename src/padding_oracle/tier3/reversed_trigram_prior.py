"""Reversed byte-trigram prior with add-k smoothing over all 256 byte values.

The attack recovers a word from its last byte to its first (D15), so when it
guesses byte i, the bytes to the RIGHT of it are already known. The prior
predicts byte i from the two bytes just to its right (a reversed trigram).

`suffix` is the recovered bytes to the right of the byte being guessed, in
word order: suffix[0] is the byte just right of it. It is empty for the last
byte of the word.

Word ends: the right end of the word is marked with two boundary bytes
(BOUNDARY, b"\\x00", which is never a letter). So the last byte is predicted
from the context "end of word", and the second-to-last byte from
"one letter, then end of word". Every context is exactly two bytes.
"""
from __future__ import annotations

from collections import Counter
from typing import Iterable

WORD_LENGTH = 8
BOUNDARY = b"\x00"  # marks the right end of a word; never part of a word


class ReversedTrigramPrior:
    """A train-word-fitted prior mapping a recovered suffix to 256 probabilities."""

    def __init__(self, words: Iterable[bytes], k: float) -> None:
        # counts[context][byte] = how many training words have `byte` followed
        # by `context` (the two bytes just to its right, boundary-padded).
        counts: dict[bytes, Counter[int]] = {}
        word_count = 0
        for word in words:
            if not isinstance(word, bytes):
                raise TypeError("each training word must be bytes")
            if len(word) != WORD_LENGTH:
                raise ValueError("each training word must contain exactly 8 bytes")
            if BOUNDARY in word:
                raise ValueError("a training word must not contain the boundary byte")
            word_count += 1
            padded = word + BOUNDARY * 2
            for index in range(WORD_LENGTH):
                context = padded[index + 1:index + 3]
                counts.setdefault(context, Counter())[padded[index]] += 1

        if word_count == 0:
            raise ValueError("at least one training word is required")
        self.training_words = word_count
        self.counts = counts
        self.totals = {context: sum(c.values()) for context, c in counts.items()}
        self.set_k(k)

    def set_k(self, k: float) -> None:
        """Change the add-k constant (used to choose k on the dev words)."""
        if not isinstance(k, (int, float)) or k <= 0:
            raise ValueError("k must be a positive number")
        self.k = float(k)

    @staticmethod
    def context(suffix: bytes) -> bytes:
        """The two bytes just right of the target, padded with boundary bytes."""
        if not isinstance(suffix, bytes):
            raise TypeError("suffix must be bytes")
        return (suffix + BOUNDARY * 2)[:2]

    def context_counts(self, suffix: bytes) -> Counter[int]:
        """Training counts for this suffix's context (empty if never seen)."""
        return self.counts.get(self.context(suffix), Counter())

    def probability(self, suffix: bytes, byte_value: int) -> float:
        """P(byte_value | suffix) = (count + k) / (context total + 256 k)."""
        context = self.context(suffix)
        count = self.counts.get(context, {}).get(byte_value, 0)
        total = self.totals.get(context, 0)
        return (count + self.k) / (total + 256 * self.k)

    def prior(self, suffix: bytes) -> tuple[float, ...]:
        """Return P(byte | suffix) for byte values 0..255, in byte-value order.

        Every value is above 0 (k > 0) and the 256 values sum to 1.
        """
        return tuple(self.probability(suffix, value) for value in range(256))

    def __call__(self, suffix: bytes) -> tuple[float, ...]:
        """Allow the fitted model itself to be called as prior(suffix)."""
        return self.prior(suffix)


def fit_reversed_trigram_prior(
    train_words: Iterable[bytes], k: float
) -> ReversedTrigramPrior:
    """Fit and return a callable reversed-trigram prior."""
    return ReversedTrigramPrior(train_words, k)
