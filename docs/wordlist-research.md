# Word List Research (Tier 2 and Tier 3)

**Project:** Padding Oracle Attacks on AES-CBC. Introduction to Cryptography, group midterm project, USTH. <br>
**Purpose:** which word list we use, how it is split for testing, and how the secret word sits in the AES block. <br>
**Audience:** owners of the word list, Tier 2 and Tier 3 tasks, and the report writer. <br>
**Status:** decided (D11, D12 and D15 in [decisions.md](decisions.md)). <br>
**Last updated:** 06/11/2026.

**Why this file exists:** Canvel's word list is cited only as "English Word List" [5] and cannot be rebuilt. We use a public list instead. Our numbers will differ from Canvel's; the report must say so.

## Contents

1. [The list and its counts](#1-the-list-and-its-counts)
2. [Why 8-letter words, and how this differs from Canvel](#2-why-8-letter-words-and-how-this-differs-from-canvel)
3. [Block layout](#3-block-layout)
4. [Test method](#4-test-method)
5. [Decision](#5-decision)
6. [Tasks](#6-tasks)
7. [Sources](#7-sources)

---

## 1. The list and its counts

**List:** SCOWL (Spell Checker Oriented Word Lists), size 85 files, American English, built with the `scowl word-list` command of the SCOWL README (exact steps in section 6, T1). **Filter:** lowercase a–z, exactly 8 letters (`len(w) == 8 and w.isalpha() and w.isascii() and w.islower()`).
**Licence:** MIT-like. Keep SCOWL's copyright notice (it also carries third-party notices) with any copy in our repo. This is a plain-language reading, not legal advice.
**Version:** GitHub `en-wl/wordlist`, branch `v2`, commit `1e5b7d3` (24/06/2026). **SHA-256 of each file:** to fill in (T1).

Counts from the team's code (05/11/2026). The files are nested: each file contains the smaller ones (checked by code).

| File | All entries | 8-letter lowercase words |
|---|---|---|
| wl60.txt | 109,140 | 12,750 |
| wl70.txt | 166,817 | 19,497 |
| wl80.txt | 241,867 | 27,828 |
| wl85.txt | 298,937 | **36,322** (the list we use) |

**Bands.** A word's band is the smallest file where it appears. A band's size is the difference between neighbouring files, so the four bands add up to 36,322 with no word counted twice. The bands show how common a word is by SCOWL's levels. They are not real word frequencies. Sizes below 60 (35, 50) belong to band A.

| Band | SCOWL sizes | Description | 8-letter words |
|---|---|---|---|
| A | up to 60 | Everyday words, the size of a default spell-checker dictionary | 12,750 |
| B | 61–70 | Less common words, found in a large spell-checker dictionary | 6,747 |
| C | 71–80 | Rarer words, still valid in current usage | 8,331 |
| D | 81–85 | The rarest valid words, often unusual or specialized | 8,494 |

**Limits:**
- Only American spelling. The result applies to American spelling; say so in one line in the report.
- SCOWL's levels come from its README. Use the README's own wording in the report.
- Not tested on Windows: nothing special needed (plain text files), but read files with `.strip()` or `.split()`.

## 2. Why 8-letter words, and how this differs from Canvel

- Canvel et al. (Sec. 4.3) selected only words of 8 characters, giving **712,786**. This is the count after filtering the Elcomsoft list [5], not the size of the whole list. It is far too large for a clean English dictionary, and why is unknown. In the report, write "an 8-character subset of a large word list".
- Our list has 36,322 eight-letter words, about 20 times fewer. Fewer candidates mean fewer sessions, so our Tier 2 numbers will **not** match 166 vs 4,239. Do not reuse C₀ = 31 or 166 as expected values.
- Canvel's analysis uses 8-byte blocks (b = 8, DES/3DES) and never mentions AES. The likely reason for 8 characters is the block size (our inference, not stated by the authors).
- All Canvel facts here were read through a summarizer tool, not the PDF. The owner of T2 (section 6) must check Sec. 4.1, 4.3, 5.2, Table 1 and reference [5] in the PDF.

## 3. Block layout

Decided in D15. AES blocks are **16 bytes**; an 8-letter word fills half a block. Layout for Tier 2 and Tier 3:

| Bytes | Content |
|---|---|
| 1–8 | A known 8-byte prefix (filler) |
| 9–16 | The 8-letter secret word |

- The attack recovers bytes from last to first, so it reaches the word first and can stop after 8 bytes. With a perfect oracle that is about 8 × 128 = 1,024 queries per block (our arithmetic, from D14).
- Because bytes come right to left, the trigram prior should predict each letter from the letters to its **right** (a reversed trigram: build the model on reversed words). This is our inference; the Tier 3 owner checks it before coding.
- The secret word is invented to measure the attack. The layout is a test setup, not a security choice.
- **Limit:** this is the easy alignment. A real system may be harder. For example, in Canvel's test the secret shared a block with the line ending and the MAC (Sec. 5.2, to check in the PDF). Our results apply to this layout only; the report says so.
- C₀ and the session numbers are recomputed for our setup.

## 4. Test method

Decided in D12.

**Why:** if the trigram prior is fitted on a word and that word is also a test word, the prior already knows the answer and the saving looks too good. A test set must not overlap the training set (Jurafsky and Martin, ch. 3).

**Steps:**
1. Take the 36,322 words, each with its band (A–D).
2. In each band: sort the words, shuffle with `random.Random(seed)`, and split by word 70% train / 10% dev / 20% test. Write the seed and the sizes in the report. Expected test sizes: about 2,550 / 1,349 / 1,666 / 1,699 words (20% of each band; our arithmetic).
3. Fit the trigram counts on the train words only (two start symbols and one end symbol per word).
4. Choose add-k on the dev words (for example a grid from 1e-4 to 1). Run the attack on the test words **once**.
5. Test words are weighted uniformly: the result is an average over the words in the list, not over what users choose.
6. Add one control row, "train = test", labelled "upper bound, leaks the answer".
7. Report results per band as a side analysis (does the gain shrink for rare words? This is an assumption to test).

**Risks to report:**
- Tuning k on the test words.
- Counting from train + dev + test and then calling the test words "unseen".
- Near-duplicate words (like run/runs) can fall on both sides of the split. This is our reasoning; no published study found.
- With 256 byte values, k = 0.01 already puts 2.56 pseudo-counts in every context, so k matters. State the alphabet size and k you used.
- Report the share of test trigrams that have zero training count, and repeat with 3 to 5 seeds to show the spread.
- Optional ablation: fit the prior on words of all lengths (removing the test words). Decide the main choice (train eight-letter words only) before looking at test results.

The 70/10/20 ratio is a convention, not a rule from a source.

## 5. Decision

- List: SCOWL wl85, American, 36,322 eight-letter words (D11).
- Split: by word, stratified by band, 70/10/20, fixed seed; test words weighted uniformly (D12).
- Block layout: 8-byte known prefix, then the 8-letter word in bytes 9–16 (D15).
- No leaked password datasets (D7).

## 6. Tasks

Full list with owners, due dates and dependencies: [tasks.md](tasks.md).

**T1: Word list and split.**
- **Build the 4 SCOWL files:**
  1. Download the SCOWL zip from GitHub `en-wl/wordlist`, branch `v2` (commit `1e5b7d3`, 24/06/2026).
  2. Build `wl60.txt`, `wl70.txt`, `wl80.txt`, `wl85.txt` with the README's `word-list` command. The README's form is `./scowl word-list 60 A 1 --deaccent > wl60.txt` (and the same for 70, 80, 85), after `make` builds `scowl.db` (needs Python 3 and SQLite). Find the way that works on your laptop (for example WSL on Windows). What must stay exact: the sizes, and `A 1 --deaccent` (US spelling, variant level 1, accents removed). These change the word counts.
  3. **Check:** the files must have exactly 109,140 / 166,817 / 241,867 / 298,937 lines.
  4. If step 2 does not work, or a count differs, stop after 30 minutes and ask Vân Khánh.
  5. Write the version and the SHA-256 of each file in `data/wordlist/README.md`.
- Keep the American eight-letter lowercase words (expect 36,322) and label each with its band A–D (expect 12,750 / 6,747 / 8,331 / 8,494). Save to a text file.
- Split each band 70/10/20 with a fixed seed (section 4); write the seed and the three sizes down.
- Put SCOWL's copyright notice next to the list in the repo.
- Write a few lines for the report (own words, not AI): which list, which version, how many words, licence, and that it is much smaller than Canvel's 712,786.
- Needed before the trigram prior (T9) and the dictionary attack (T8a).

**T2: Read Canvel sections 2–4 and check the facts.**
- Open Sec. 4.1, 4.3, 5.2, Table 1 and reference [5] in the PDF and check every Canvel fact we use.
- Confirm why Canvel used 8-letter words.
- Write a one-page list of the facts checked (number, section, exact setup) for the Tier 2 and Tier 3 owners and the report writer.
- Same person as the Tier 3 owner.

## 7. Sources

- SCOWL README (branch `v2`): https://github.com/en-wl/wordlist/blob/v2/README.md
- SCOWL source repo: https://github.com/en-wl/wordlist
- Canvel et al. 2003: https://www.iacr.org/archive/crypto2003/27290581/27290581.pdf
- Jurafsky and Martin, SLP3 ch. 3: https://web.stanford.edu/~jurafsky/slp3/3.pdf
- Chen and Goodman 1996: https://arxiv.org/pdf/cmp-lg/9606011