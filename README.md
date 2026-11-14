# crypto-padding-oracle-attack

Padding oracle attacks on AES-CBC: reproduction, a prior-aware attack on noisy oracles, and countermeasures — Group project for Introduction to Cryptography course.

## Local setup

```powershell
python -m pip install -r requirements.txt
$env:PYTHONPATH = ".\src"
python -m pytest
python .\scripts\run_harness_demo.py
```
