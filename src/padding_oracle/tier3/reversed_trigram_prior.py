"""Reversed byte-trigram prior with add-k smoothing over all 256 byte values.

The suffix is ordered from nearest byte to farthest byte on the right.
For suffixes of length >= 2, the first two bytes form the reversed-trigram
context. A one-byte suffix uses a bigram context; an empty suffix uses
unigram counts. Every returned probability is strictly positive when k > 0.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Iterable


class ReversedTrigramPrior:
    """A train-word-fitted prior mapping a recovered suffix to 256 probabilities."""

    def __init__(self, words: Iterable[bytes], k: float) -> None:
        if not isinstance(k, (int, float)) or k <= 0:
            raise ValueError("k must be a positive number")
        self.k = float(k)
        self.unigram: Counter[int] = Counter()
        self.bigram: dict[bytes, Counter[int]] = defaultdict(Counter)
        self.trigram: dict[bytes, Counter[int]] = defaultdict(Counter)

        word_count = 0
        for word in words:
            if not isinstance(word, bytes):
                raise TypeError("each training word must be bytes")
            if len(word) != 8:
                raise ValueError("each training word must contain exactly 8 bytes")
            word_count += 1
            for index, target in enumerate(word):
                suffix = word[index + 1:]
                self.unigram[target] += 1
                if len(suffix) >= 1:
                    self.bigram[suffix[:1]][target] += 1
                if len(suffix) >= 2:
                    self.trigram[suffix[:2]][target] += 1

        if word_count == 0:
            raise ValueError("at least one training word is required")
        self.training_words = word_count

    def prior(self, suffix: bytes) -> tuple[float, ...]:
        """Return P(byte | suffix) for byte values 0..255, in byte-value order."""
        if not isinstance(suffix, bytes):
            raise TypeError("suffix must be bytes")

        if len(suffix) >= 2:
            counts = self.trigram.get(suffix[:2], {})
        elif len(suffix) == 1:
            counts = self.bigram.get(suffix[:1], {})
        else:
            counts = self.unigram

        denominator = sum(counts.values()) + 256 * self.k
        probabilities = tuple(
            (counts.get(byte_value, 0) + self.k) / denominator
            for byte_value in range(256)
        )
        # The construction guarantees positivity and normalization.
        return probabilities

    def __call__(self, suffix: bytes) -> tuple[float, ...]:
        """Allow the fitted model itself to be called as prior(suffix)."""
        return self.prior(suffix)


def fit_reversed_trigram_prior(
    train_words: Iterable[bytes], k: float
) -> ReversedTrigramPrior:
    """Fit and return a callable reversed-trigram prior."""
    return ReversedTrigramPrior(train_words, k)
