# SCOWL word list

Source: [SCOWL / English Speller Database](https://github.com/en-wl/wordlist), branch `v2`, commit `1e5b7d3a72f47a71da5d28686c1dd4b397178485` (24 June 2026). The four generated source lists use American spelling (`A`), maximum variant level `1`, and `--deaccent`. `SCOWL-Copyright` contains the source attribution and notices.

`words8.csv` contains exactly 36,322 unique, lowercase ASCII words of length eight. Bands are assigned to the first nested SCOWL list containing each word; the counts are A/B/C/D = 12,750 / 6,747 / 8,331 / 8,494.

The split is stratified by band. With seed `42`, the builder sorts each band, shuffles it using one `random.Random(42)` instance, assigns rounded 70% to train and 10% to dev, and assigns the remainder to test. The resulting train/dev/test counts are:

| Band | Train | Dev | Test |
|---|---:|---:|---:|
| A | 8,925 | 1,275 | 2,550 |
| B | 4,723 | 675 | 1,349 |
| C | 5,832 | 833 | 1,666 |
| D | 5,946 | 849 | 1,699 |
| **Total** | **25,426** | **3,632** | **7,264** |

Rebuild the four flat source lists from the pinned SCOWL checkout with:

```powershell
# Or clone the v2 branch, then check out the pinned commit.
git clone --branch v2 https://github.com/en-wl/wordlist C:\path\to\wordlist-checkout
git -C C:\path\to\wordlist-checkout checkout 1e5b7d3a72f47a71da5d28686c1dd4b397178485
python .\scripts\extract_scowl_lists.py --scowl-dir C:\path\to\wordlist-checkout
```

The extraction script verifies the checked-out commit (or the exact folder name from the pinned GitHub archive), creates the database in a temporary directory, uses the pinned SCOWL commands, verifies each line count, and writes UTF-8 bytes consistently on Windows. Then from the project root run:

```powershell
python .\scripts\build_wordlist.py --source-dir .\data\wordlist\source
```

The builder validates source line counts, uniqueness, nested-set relationships, and each band count before writing the CSV sorted by word.

## SHA-256

| File | SHA-256 |
|---|---|
| `source/wl60.txt` | `7B63ED6DAC6D984FB5F7C47CD14E5559A1B1B34F2E4E7ED3D36B76B3259B6191` |
| `source/wl70.txt` | `842220893265CF36FC0D3AE997D78ECA5235C8FA20971ED629EC6659454CC881` |
| `source/wl80.txt` | `E3CC05991BC057E8FB171C12ABA4C7464228445DBC3433314A59093E325D84C2` |
| `source/wl85.txt` | `91B42251C8254E88CC9C5DD004B84EA151F85D5142926843F546D4C5553B08B6` |
| `words8.csv` | `A53D9B52B0F9A560A8822D2A25C983A0C4FF19393AC4CC7B8A92087D7D0A7241` |
