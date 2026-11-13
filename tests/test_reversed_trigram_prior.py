from padding_oracle.tier3.reversed_trigram_prior import ReversedTrigramPrior
import pytest


@pytest.fixture
def prior():
    """Fit the prior on a few eight-byte training words."""
    train_words = [
        b"abcdefgh",
        b"ijklmnop",
        b"qrstuvwx",
    ]
    return ReversedTrigramPrior(train_words, k=0.1)


@pytest.mark.parametrize("suffix", [b"", b"a", b"ab"])
def test_prior_returns_valid_probability_distribution(prior, suffix):
    probabilities = prior.prior(suffix)

    assert len(probabilities) == 256
    assert all(p > 0 for p in probabilities)
    assert sum(probabilities) == pytest.approx(1.0)


def test_unseen_suffix_still_returns_positive_probabilities(prior):
    # This byte sequence does not occur as a training context.
    unseen_suffix = b"\xfe\xff"

    probabilities = prior.prior(unseen_suffix)

    assert len(probabilities) == 256
    assert all(p > 0 for p in probabilities)
    assert sum(probabilities) == pytest.approx(1.0)


def test_last_byte_uses_the_end_of_word_context(prior):
    # Training words end in h, p, x, so an empty suffix (last byte of a word)
    # should favour those over a letter that never ends a word.
    probabilities = prior.prior(b"")

    assert probabilities[ord("h")] > probabilities[ord("z")]


def test_seen_context_favours_the_trained_byte(prior):
    # In "abcdefgh" the byte before "bc" is "a".
    probabilities = prior.prior(b"bc")

    assert probabilities[ord("a")] > probabilities[ord("z")]


def test_longer_suffix_uses_only_the_two_nearest_bytes(prior):
    assert prior.prior(b"bcdefgh") == prior.prior(b"bc")

