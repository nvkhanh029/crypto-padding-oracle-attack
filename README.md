# crypto-padding-oracle-attack

Padding oracle attacks on AES-CBC: reproduction, a prior-aware attack on noisy oracles, and countermeasures — Group project for Introduction to Cryptography course.

## Local setup

```powershell
python -m pip install -r requirements-dev.txt
$env:PYTHONPATH = ".\src"
python -m pytest
python .\scripts\run_task_demos.py
```

The demo writes the stub harness row to `results/`. SCOWL source generation and the word-list split are documented in [`data/wordlist/README.md`](data/wordlist/README.md).
