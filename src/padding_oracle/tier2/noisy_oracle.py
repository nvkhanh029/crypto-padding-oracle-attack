"""T6: the noisy timing oracle (simulated).

Server type 2 says the same thing for a correct and a wrong padding, but it
takes slightly longer when the padding is correct. This oracle turns a perfect
padding oracle into that server: every `query()` returns ONE Gaussian timing
sample, in "time units", and never the true yes/no.

Timing inputs (from docs/decisions.md; T2 confirms them against Canvel):
    mu_r  = 23.63  mean time when the padding is right
    mu_w  = 21.57  mean time when the padding is wrong
    sigma =  1.86  standard deviation of the noise
The gap between the means is about the size of the noise, so one sample is
not enough to decide. T7, T8a, T10 and T11 ask again and again.

The query counter comes from `NoisyOracle`/`BaseOracle`: it goes up by exactly
1 per `query()` call, and `reset()` sets it to 0. The inner padding check is
not counted, because this oracle calls the perfect oracle's `_answer` directly.

`noise=False` is the noise-off mode: the oracle returns the exact mean
(mu_r or mu_w) with no random part. It is deterministic, so Tier 2 recovers
the same plaintext as Tier 1 with it (the D14 pattern check). The real oracle
is never used with the noise off in the report; it is a debugging and
comparison mode.

Example
-------
    from padding_oracle.core.fakes import FakePerfectOracle
    from padding_oracle.tier2 import GaussianTimingOracle

    oracle = GaussianTimingOracle(FakePerfectOracle(), seed=42)
    t = oracle.query(ciphertext)       # one float, e.g. 24.7
    assert oracle.queries == 1

Python 3.11+.
"""

from __future__ import annotations

import random

from ..core.contracts import BaseOracle, NoisyOracle, PerfectOracle

# Timing inputs, in "time units" (see docs/decisions.md, Canvel et al. 2003).
MU_R = 23.63   # mean when the padding is Right (valid)
MU_W = 21.57   # mean when the padding is Wrong (invalid)
SIGMA = 1.86   # standard deviation of the noise


class GaussianTimingOracle(NoisyOracle):
    """Timing side channel around a perfect padding oracle.

    `perfect_oracle` supplies the truth (T3b AES oracle in experiments, the
    fake perfect oracle in tests). `seed` makes the noise repeatable. The
    parameters `mu_r`, `mu_w` and `sigma` default to the Canvel inputs above;
    they are inputs to the simulation, never measured results.

    Set the public attribute `noise` to False for the noise-off mode (or pass
    `noise=False` to the constructor). With the noise off every sample is the
    exact mean, so the attacker can classify it perfectly with any threshold
    between `mu_w` and `mu_r`.
    """

    def __init__(
        self,
        perfect_oracle: PerfectOracle,
        seed: int | None = None,
        mu_r: float = MU_R,
        mu_w: float = MU_W,
        sigma: float = SIGMA,
        noise: bool = True,
    ) -> None:
        super().__init__()
        if not isinstance(perfect_oracle, BaseOracle):
            raise TypeError("perfect_oracle must be a BaseOracle (PerfectOracle)")
        if sigma < 0:
            raise ValueError("sigma must be 0 or positive")
        self._inner = perfect_oracle
        self.mu_r = float(mu_r)
        self.mu_w = float(mu_w)
        self.sigma = float(sigma)
        self.noise = bool(noise)
        self._rng = random.Random(seed)

    def _answer(self, ciphertext: bytes) -> float:
        # Ask the inner oracle's _answer, not its query(), so the inner
        # padding check does not touch any counter and is not counted twice.
        valid = bool(self._inner._answer(ciphertext))
        mean = self.mu_r if valid else self.mu_w
        if not self.noise:
            return mean
        return self._rng.gauss(mean, self.sigma)
