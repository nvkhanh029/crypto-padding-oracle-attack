# Padding Oracle Attacks on AES-CBC

Reproducing Vaudenay and Canvel, and Evaluating a Prior-Aware Attack on Noisy Oracles. Group project for the Introduction to Cryptography course.

Everything runs in pure Python, in simulation, on a normal laptop (no GPU, no network). The code needs Python 3.11 or newer.

## Run the demo

Open a terminal in the repository folder.

**Windows (PowerShell)**

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts\run_harness_demo.py
```

**macOS / Linux**

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pytest -q
.venv/bin/python scripts/run_harness_demo.py
```

- `pytest` runs all tests (about 20 seconds). All of them should pass.
- The demo takes about 1 second. It runs the evaluation harness three times and writes three small CSV files into `results/`:
  - `harness_stub_smoke.csv`: the harness on a stub attack.
  - `tier1_harness.csv`: the Vaudenay attack recovers one random AES-CBC block with a perfect oracle (`success` = 1, `queries` = about 2,000).
  - `tier2_harness_noise_off.csv`: the dictionary attack recovers one 8-letter word (noise switched off).
- The seed is fixed (42), so the demo gives the same files every time.

If `python` is not found on Windows, try `py` instead (for example `py -m venv .venv`).

## What is in the repository

| Folder | Content |
|---|---|
| `src/padding_oracle/` | The code: `core/` (shared rules and fake oracles), `tier1/` (AES-CBC, perfect oracle, Vaudenay attack), `countermeasures/` (Encrypt-then-MAC and AES-GCM servers), `tier2/` (noisy oracle, Canvel's sequential test, dictionary attack), `tier3/` (trigram prior, posterior-threshold attack, baselines, experiments), `harness/` (evaluation harness) |
| `tests/` | Tests, run with `python -m pytest` |
| `results/` | Results of the experiments (one CSV per experiment) |
| `figures/` | Figures for the report |
| `data/wordlist/` | The word list (SCOWL) and how it was built and split |
| `docs/` | Decisions, tasks, contracts and notes of the team |
| `scripts/` | Helper scripts, including the demo |

## Word list licence

The word list comes from SCOWL. Its copyright notice is in `data/wordlist/SCOWL-Copyright`.