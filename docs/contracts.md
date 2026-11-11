# Contracts

**Project:** Padding Oracle Attacks on AES-CBC. Introduction to Cryptography, group midterm project, USTH.
**Purpose:** what the shared rules in the code mean, why we chose them, and how to use the fake oracles.
**Audience:** all team members, and any AI tool helping with code (paste this file into it).
**Last updated:** 11/11/2026.

> **Exact names are in `src/padding_oracle/core/contracts.py`. If this document and that file disagree, the code is right.**

Related documents: [tasks.md](tasks.md), [decisions.md](decisions.md), [wordlist-research.md](wordlist-research.md), [canvel-fact-check.md](canvel-fact-check.md).

---

## 1. The rule for everyone

- Build and test your module against the **fake oracles** (`core/fakes.py`).
- An attack **receives** its oracle as a parameter. It never creates one. So the same attack runs against the fake oracle, the real oracle and the countermeasure servers.
- When the real oracle is merged (T3b perfect, T6 noisy), use the real one for experiments. Smoke tests keep using the fake one (fast, no AES library).
- Never count queries yourself. The oracle counts.
- Python 3.11 or newer.

## 2. The oracle

| Item | Rule | Why |
|---|---|---|
| Input | `oracle.query(ciphertext: bytes)`. The ciphertext is the IV followed by 16-byte blocks: length a multiple of 16 and at least 32. | It works like a real server. The countermeasure servers (T5: Encrypt-then-MAC, AES-GCM) use the same call, so the Tier 1 attack runs on them unchanged and we can show it fails. |
| Perfect oracle | Returns `bool`: `True` = padding valid. | Server type 1 (different error messages). |
| Noisy oracle | Returns `float`: one timing sample, in **milliseconds**. It never reveals the truth. | Server type 2 (same message, small timing difference). Tiers 2 and 3 must decide from repeated samples. |
| Counter | `oracle.queries` goes up by exactly 1 per `query()` call. `oracle.reset()` sets it to 0. The noisy oracle's inner padding check is not counted. A rejected (malformed) ciphertext is not counted. | One place to count, so no attack can forget or count twice (D14: a query counted twice gives +100% error and Tier 1 would fail). |

**Timing unit:** milliseconds, as in Canvel's Fig. 3 ("Time (in 1/1000s)"). The values μ_R ≈ 23.63, μ_W ≈ 21.57, σ ≈ 1.86 are inputs from `decisions.md`. No yes/no flip-noise mode for now (optional, added later if needed).

## 3. The fake oracles

- `FakePerfectOracle`: toy block cipher (XOR with a fixed key) with **real** CBC and **real** PKCS#7 padding. Not secure, and not meant to be.
- `FakeNoisyOracle`: wraps the fake perfect oracle and returns one Gaussian timing sample (mean μ_R if the padding is valid, μ_W if not, standard deviation σ).
- Why a toy cipher works: a padding-oracle attack only uses the CBC XOR step and the padding check, never the inside of the block cipher. So code written against the fakes keeps working with real AES.
- The fakes stay in the repo as test helpers. Nobody has to "fix" them later. The oracle's class name is written in every results file (`oracle` column), so a result produced with a fake is easy to spot.
- Helpers for tests: `fake_cbc_encrypt(plaintext, iv)` builds a ciphertext (IV + blocks).

## 4. Function shapes

**Every attack** has this shape (T4, T7/T8a, T10, T11 and the harness use it):

```python
def attack(oracle, ciphertext: bytes, n_bytes: int, **params) -> bytes
```

- `ciphertext`: exactly two blocks (32 bytes), the previous block (or IV) plus the target block. All experiments attack one block at a time.
- `n_bytes`: how many bytes to recover, from the end of the block: 16 (Tier 1) or 8 (the D15 word layout).
- `params`: attack settings (for example δ, k). They are also written to the `params` CSV column.
- Returns the recovered bytes. The harness compares them with the truth (`success`) and reads `oracle.queries` (`queries`).

**The Canvel-style sequential test** (T7 provides it, T8a calls it):

```python
def sequential_check(oracle, ciphertext: bytes, **params) -> bool
```

It asks the noisy oracle about the same ciphertext again and again until it is confident, then returns `True` (padding judged valid) or `False`. The thresholds go in `params`; their values are T7's job. This matches Canvel's `Check4` (Fig. 5): it takes only the tested ciphertext, with the same thresholds for every candidate.

**Stubs** (`fakes.py`): `stub_attack` (one query, returns zero bytes) lets the harness (T12a) run before any real attack exists. `stub_sequential_check` (one sample, compared with the middle of the two means) lets T8a start before T7 is merged. Replace them when the real ones are merged.

## 5. Results file (one CSV per experiment, in `results/`)

One row = **one attack on one target** (one random block or one test word). Success rate, error rate and the Tier 1 confidence interval are computed from the rows, so keep the raw rows. Comma separated, UTF-8, one header row, columns in this order:

| Column | Meaning | Example |
|---|---|---|
| `experiment` | Groups rows | `tier1_reproduction` |
| `attack` | Which attack | `vaudenay`, `posterior_trigram` |
| `oracle` | Oracle class name | `FakePerfectOracle`, `PerfectOracle` |
| `seed` | Integer, to repeat the run | `42` |
| `target` | The target | `random_block_017` or the secret word |
| `band` | `A`–`D` for a word, empty for a random block | `C` |
| `bytes_attacked` | Bytes recovered | `16` or `8` |
| `queries` | `oracle.queries` after the attack | `2051` |
| `success` | `1` if every attacked byte is correct, else `0` | `1` |
| `params` | Settings as text, may be empty | `delta=0.001;k=...` |

δ = 0.001 (D18). k is not chosen yet (chosen on dev, D12). Not included on purpose: timing per query and a git-commit column (no task needs them).

## 6. Word list file

`data/wordlist/words8.csv`: header `word,band,split`, for example `abandons,A,train`. Sorted by word, lowercase a–z, UTF-8, 36,322 rows. Bands `A`–`D`; splits `train`, `dev`, `test`. The seed and the SCOWL version go in `data/wordlist/README.md`; SCOWL's copyright notice is in its own file. Details: [wordlist-research.md](wordlist-research.md).
