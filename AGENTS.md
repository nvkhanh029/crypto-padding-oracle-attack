# AGENTS.md

Rules for AI coding tools (and humans) working in this repository. Follow them from the first line of code.

## 1. Project

Padding oracle attacks on AES-CBC, in pure Python, all in simulation:
- **Tier 1:** reproduce Vaudenay (2002) with a perfect oracle; Encrypt-then-MAC and AES-GCM stop the attack.
- **Tier 2:** reproduce Canvel et al. (2003) with a simulated noisy timing oracle and a dictionary attack.
- **Tier 3:** a prior-aware posterior-threshold attack on the noisy oracle, compared with baselines.

Background and decisions: `docs/decisions.md`. Tasks and owners: `docs/tasks.md`.

## 2. Basic rules

- **Python 3.11 or newer.** CI runs on 3.11 and on the newest version.
- **Keep code simple and explainable.** Every task owner must be able to explain their code in their own words. Prefer plain loops and clear names over clever tricks. Short docstrings on public functions.
- **Do not invent results.** Never write numbers, results or expected values into code, comments, tests or docs that were not produced by running our code. Never hard-code a result to make a test pass.
- **Do not add dependencies** outside `requirements.txt` without asking the task owner and the Lead.
- **Randomness is seeded.** Every experiment takes a `seed` and uses `random.Random(seed)` (or a seeded generator), never the global random state. The seed is written to the results CSV.
- **No report text.** The report is written by the team in Overleaf, not by AI and not in this repo.
- **No leaked password datasets.** The only word list is SCOWL (`data/wordlist/`). Keep SCOWL's copyright notice next to it.
- **Stay in your task.** Change only the files of the task you are working on. Do not edit `src/padding_oracle/core/` unless the task is T0a or the Lead agrees.

## 3. Folder layout

```
src/padding_oracle/
  core/             shared contracts, oracle interface, fake oracles (T0a)
  tier1/            AES-CBC, PKCS#7, perfect oracle, Vaudenay attack (T3, T4)
  countermeasures/  Encrypt-then-MAC and AES-GCM servers (T5)
  tier2/            noisy oracle, Canvel sequential test, dictionary attack (T6, T7, T8a)
  tier3/            trigram prior, posterior-threshold attack, baselines (T9, T10, T11)
  harness/          evaluation harness (T12a)
data/wordlist/      SCOWL list, its copyright notice, the split (T1)
results/            experiment CSVs (format in section 5)
figures/            figures for the report (PNG or PDF)
tests/              smoke tests
docs/               shared project documents
```

Put new code in the folder of its tier. Do not create new top-level folders.

## 4. Shared contracts

Two files, with different jobs:
- `src/padding_oracle/core/contracts.py`: the **exact names** (classes, methods, columns). Import from it; never copy names by hand.
- `docs/contracts.md`: what each part means and why we chose it.

If the two disagree, the code is right. The summary below is for orientation only; exact names are in `contracts.py`.

### 4.1 Oracle interface

- Call: `oracle.query(ciphertext: bytes)`.
  - `ciphertext` = IV + ciphertext blocks. Length is a multiple of 16 and at least 32.
  - The countermeasure servers (T5) use the same call.
- **Perfect oracle** returns `bool`: `True` = padding OK, `False` = padding wrong.
- **Noisy oracle** returns `float`: one timing sample, in "time units". It never reveals the true answer.
  - Timing inputs: μ_R ≈ 23.63 (padding right), μ_W ≈ 21.57 (padding wrong), σ ≈ 1.86. These are inputs, not results.
- **Query counter** lives inside the oracle:
  - `oracle.queries` goes up by exactly 1 per `query()` call.
  - `oracle.reset()` sets it to 0.
  - The noisy oracle's inner padding check is **not** counted.
  - A malformed ciphertext is rejected and **not** counted.
- Attacks must count queries only through `oracle.queries`. Do not keep a separate counter.

### 4.2 Fake oracles

- `core/fakes.py` has a fake perfect oracle (toy block cipher: XOR with a fixed key, real CBC, real PKCS#7 padding) and a fake noisy oracle that wraps it.
- The fakes are test helpers and stay in the repo. The real oracles come from T3b (perfect) and T6 (noisy).

### 4.3 Attack functions

- Every attack has this shape:
  `attack(oracle, ciphertext, n_bytes, **params) -> bytes`
  - `oracle`: passed in as a parameter. No automatic switch from fake to real in code.
  - `ciphertext`: exactly two blocks (32 bytes).
  - `n_bytes`: 16 (Tier 1, full block) or 8 (Tiers 2–3, the word in bytes 9–16).
  - `**params`: method settings (thresholds, δ, k, ...).
  - Returns the recovered bytes. The attack does **not** check success or count queries; the harness does both (it compares the bytes and reads `oracle.queries`).
- The T7 sequential test has this shape:
  `sequential_check(oracle, ciphertext, **params) -> bool`
  It draws repeated noisy samples and decides "padding OK" or not; thresholds go in `params`.
- Build and test against the fake. Once the real oracle is merged, use the real one for experiments. Smoke tests keep using the fake.

### 4.4 Word list file

- One file: `data/wordlist/words8.csv`, columns `word,band,split` (e.g. `abandons,A,train`).
- Sorted by word, lowercase a–z, UTF-8, one header row, 36,322 rows.
- `band` is A–D; `split` is `train`, `dev` or `test`.
- The seed and the SCOWL version are in `data/wordlist/README.md`. SCOWL's copyright notice is in its own file there.
- **Never fit a prior on `dev` or `test` words.** Choose k on `dev`; run `test` once.

## 5. Results CSV

- One CSV per experiment in `results/`. Comma separated, UTF-8, one header row.
- **One row = one attack on one target** (one random block or one test word).
- Columns, in this order:

| Column | Meaning |
|---|---|
| `experiment` | experiment name |
| `attack` | attack name |
| `oracle` | oracle name |
| `seed` | random seed |
| `target` | the target (block or word) |
| `band` | A–D for a word; empty for a random block |
| `bytes_attacked` | 16 (full block) or 8 (word) |
| `queries` | `oracle.queries` at the end of the attack |
| `success` | 1 if all attacked bytes are correct, else 0 |
| `params` | text, e.g. `delta=...;k=...` |

- Success rate, error rate and confidence intervals are computed from the rows, not stored.
- Do not add per-query timing or git-commit columns.

## 6. Git

### 6.1 Commit messages (Conventional Commits)

`type(scope): summary`, with type `feat`, `docs` or `chore`. Examples:
- `feat(tier1): add perfect oracle`
- `docs(report): add background draft`
- `chore(ci): add smoke tests`

### 6.2 Branches

- One branch per task (not per member), one PR per branch. Delete the branch after merge.
- Name: `type/short-name`, lowercase with hyphens, type as in the commit style.
- Use the branch name of your task from this list. If a task changes owner, the name stays.

| Task | Branch |
|---|---|
| T0a | `chore/core-contracts-stubs` |
| T0b | `chore/repo-ci-agents` |
| E1 | `docs/explainer-sheet` |
| M1 | `chore/final-merge` |
| T1 | `feat/wordlist-split` |
| T2 | `docs/canvel-fact-check` |
| T3a | `feat/tier1-aes-cbc-padding` |
| T3b | `feat/tier1-perfect-oracle` |
| T4 | `feat/tier1-vaudenay-attack` |
| T5a | `feat/countermeasures-server-functions` |
| T5b | `feat/countermeasures-attack-fails` |
| T6 | `feat/tier2-noisy-oracle` |
| T7 | `feat/tier2-canvel-sequential` |
| T8a | `feat/tier2-dictionary-attack` |
| T8b | `feat/tier2-experiments` |
| T9 | `feat/tier3-trigram-prior` |
| T10 | `feat/tier3-posterior-attack` |
| T11 | `feat/tier3-baselines` |
| T12a | `feat/harness` |
| T12b | `feat/tier3-experiments` |
| T13 | `docs/figure-three-servers` |
| T13b | `docs/figure-cbc-attack` |

### 6.3 Pull requests

- `main` is protected: a PR, 1 approval and passing CI are required.
- A PR is accepted only with **CI passing** and a **screenshot or short video** showing the feature works.
- Results are saved in the CSV format of section 5.
- The PR description has 5–8 bullet notes plus the results, written by the owner in their own words (no AI). These notes are the input for the report.
- Review order is in `docs/tasks.md`, section 3.
- The owner fixes their own bugs after review.

## 7. Tests

- Smoke tests live in `tests/` and run in CI. They use the fake oracles and small cases, so they run in seconds. The contract tests are in `tests/test_core_contracts.py`; keep them passing.
- **Run `python -m pytest` from the repo root before every commit and before opening a PR.** Fix failing tests before you push.
- The repo sets `pythonpath = src` in its pytest settings, so you do not need `PYTHONPATH`. On Windows, bare `pytest` is often "not recognized" (its Scripts folder is not on PATH), so always run `python -m pytest`; it works the same on Mac, Linux and CI.
- A new attack gets at least one small test: it recovers the right bytes on the fake oracle.