"""FAKE oracles and stubs (T0a), so later tasks can start without waiting.

These are TEST HELPERS. They stay in the repo for the smoke tests and for
early development. They are not the real oracles:

- The real perfect oracle (AES-CBC) comes from T3b (Kien).
- The real noisy oracle comes from T6 (Hai).

The fake "block cipher" is XOR with a fixed key. It is NOT secure and is not
meant to be. A padding-oracle attack only uses the CBC XOR step and the
padding check, never the inside of the block cipher, so code written against
these fakes keeps working when the real AES oracles replace them.

CBC and PKCS#7 padding here are the real thing.
"""

from __future__ import annotations

import random

from .contracts import BLOCK_SIZE, BaseOracle, NoisyOracle, PerfectOracle

# Fixed key of the toy cipher (16 bytes). Not secret, not secure.
FAKE_KEY = bytes(range(1, BLOCK_SIZE + 1))

# Timing inputs for the fake noisy oracle, in milliseconds (Canvel 2003,
# Fig. 3). These come from docs/decisions.md.
MU_R = 23.63   # mean time when the padding is Right (valid)
MU_W = 21.57   # mean time when the padding is Wrong (invalid)
SIGMA = 1.86   # standard deviation of the noise


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def toy_block_decrypt(block: bytes) -> bytes:
    """The fake block cipher, decrypt direction (XOR with FAKE_KEY)."""
    return _xor(block, FAKE_KEY)


def toy_block_encrypt(block: bytes) -> bytes:
    """The fake block cipher, encrypt direction (XOR is its own inverse)."""
    return _xor(block, FAKE_KEY)


def pkcs7_pad(data: bytes) -> bytes:
    """PKCS#7: add n bytes, each with the value n (1 <= n <= 16)."""
    n = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([n]) * n


def pkcs7_padding_ok(plaintext: bytes) -> bool:
    """True if the last bytes are valid PKCS#7 padding."""
    if not plaintext or len(plaintext) % BLOCK_SIZE != 0:
        return False
    n = plaintext[-1]
    if n < 1 or n > BLOCK_SIZE:
        return False
    return plaintext[-n:] == bytes([n]) * n


def fake_cbc_encrypt(plaintext: bytes, iv: bytes) -> bytes:
    """Pad, then CBC-encrypt with the toy cipher. Returns IV + blocks."""
    if len(iv) != BLOCK_SIZE:
        raise ValueError("iv must be 16 bytes")
    padded = pkcs7_pad(plaintext)
    out = [iv]
    prev = iv
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i + BLOCK_SIZE]
        c = toy_block_encrypt(_xor(block, prev))
        out.append(c)
        prev = c
    return b"".join(out)


def fake_cbc_decrypt_raw(ciphertext: bytes) -> bytes:
    """CBC-decrypt with the toy cipher, WITHOUT removing padding."""
    iv, body = ciphertext[:BLOCK_SIZE], ciphertext[BLOCK_SIZE:]
    out = []
    prev = iv
    for i in range(0, len(body), BLOCK_SIZE):
        c = body[i:i + BLOCK_SIZE]
        out.append(_xor(toy_block_decrypt(c), prev))
        prev = c
    return b"".join(out)


class FakePerfectOracle(PerfectOracle):
    """Fake perfect oracle: returns True if the padding is valid, else False.

    Counts exactly one query per `query()` call (done by BaseOracle).
    """

    def _answer(self, ciphertext: bytes) -> bool:
        return pkcs7_padding_ok(fake_cbc_decrypt_raw(ciphertext))


class FakeNoisyOracle(NoisyOracle):
    """Fake noisy oracle: one Gaussian timing sample per query.

    It wraps a FakePerfectOracle to know the truth, then adds noise: the sample
    has mean MU_R if the padding is valid and MU_W if not, with standard
    deviation SIGMA. The truth is never returned.

    The inner padding check is NOT counted: only calls to THIS oracle's
    `query()` count, once each.
    """

    def __init__(self, seed: int | None = None, mu_r: float = MU_R,
                 mu_w: float = MU_W, sigma: float = SIGMA) -> None:
        super().__init__()
        self._inner = FakePerfectOracle()
        self._rng = random.Random(seed)
        self.mu_r, self.mu_w, self.sigma = mu_r, mu_w, sigma

    def _answer(self, ciphertext: bytes) -> float:
        # Call the inner oracle's _answer, not its query(), so the inner
        # check does not touch any counter.
        valid = self._inner._answer(ciphertext)
        mean = self.mu_r if valid else self.mu_w
        return self._rng.gauss(mean, self.sigma)


# --- Stubs -----------------------------------------------------------------

def stub_attack(oracle: BaseOracle, ciphertext: bytes, n_bytes: int,
                **params) -> bytes:
    """Stub of the `Attack` shape, for the harness (T12a).

    It does one query (so the counter moves) and returns placeholder zero
    bytes. It does NOT attack anything. Replace it with the real attack
    (T4, T7/T8a, T10, T11) when those are merged.
    """
    oracle.query(ciphertext)
    return bytes(n_bytes)


def stub_sequential_check(oracle: BaseOracle, ciphertext: bytes,
                          **params) -> bool:
    """Stub of the T7 `SequentialCheck` shape, so T8a can run.

    Asks the noisy oracle ONCE and compares the sample with the middle of the
    two means. This is a dummy body: the real sequential test (repeated
    samples, thresholds tau) is T7's job (Hai); the signature stays the same.
    """
    mid = params.get("threshold", (MU_R + MU_W) / 2)
    return oracle.query(ciphertext) > mid
