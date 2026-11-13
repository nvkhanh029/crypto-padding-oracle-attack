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