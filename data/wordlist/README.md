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

Hashes of the files as stored in the repo (LF line endings).

| File | SHA-256 |
|---|---|
| `source/wl60.txt` | `45A4DD29B86234FBABCE26F33272466BB5572DB6FDCA1470C4F218E6B666A56D` |
| `source/wl70.txt` | `8363339AF936F7A0C5100993915D55D3DD1523700B921647B59FEAE2957CF67B` |
| `source/wl80.txt` | `8A9B3ADB39508D7769F8CD5D01B49FC3B8A2217E7D743B4016B1454877E0D939` |
| `source/wl85.txt` | `821FEFAB16A93923B3B748A4F266BF8101E0EC09C78566A44F67A059CE3B191C` |
| `words8.csv` | `A53D9B52B0F9A560A8822D2A25C983A0C4FF19393AC4CC7B8A92087D7D0A7241` |
