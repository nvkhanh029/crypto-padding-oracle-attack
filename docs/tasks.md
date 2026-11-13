# Tasks and Work Split

**Project:** Padding Oracle Attacks on AES-CBC. Introduction to Cryptography, group midterm project, USTH. <br>
**Purpose:** who does what, by when, and what must be ready before a task can start. <br>
**Audience:** all team members. <br>
**Last updated:** 13/11/2026.

| Key dates | |
|---|---|
| Deadline | 15/11/2026, 23:00 |
| Final freeze | Sat 14/11 |

Related documents: [decisions.md](decisions.md), [wordlist-research.md](wordlist-research.md), [report-outline.md](report-outline.md), [contracts.md](contracts.md).

---

## 1. Who does what

| Member | Tasks |
|---|---|
| Vân Khánh (Lead) | T0a, T0b, E1, M1 |
| An Khánh | T2, T10, R4 |
| Duy (report owner) | R1, R2, R3, R5, R6 |
| Kiên | T3, T4, T9 |
| Hải | T6, T7, T11, T12b |
| Linh | T8a, T13b, T8b |
| Minh | T1, T13, T5, T12a |

## 2. Calendar and rules

- Day 1 = Fri 06/11.
- Check-ins: Mon 09/11, Wed 11/11, Fri 13/11. Final freeze: Sat 14/11. The board and the commit log are looked at in every check-in.
- Sat 07/11 evening: each owner posts a 2-line status in the group chat (no meeting).
- Owners of T3, T4 and T9 post a one-line update in the group chat every day until their task is merged.
- Start on the T0a stubs: a task does not wait for the module it depends on. Build against the stub, then switch to the real module when it is merged.
- A task is done when: CI passes, a screenshot or short video shows it works, results are saved in the format from T0a, and the owner can explain the code in their own words.
- PRs sent on Sat 07/11 are reviewed on Mon 09/11.
- If a task slips, say it at once in the group chat. Tasks are re-split and reassigned, not dropped.
- Report input: every owner of a task that produces results writes 5–8 bullet notes plus the results in the PR description, in their own words (no AI). Duy writes the report from these PR notes. Each owner also reads Duy's paragraph about their part.

## 3. Reviews and backups

| Author | Reviewer |
|---|---|
| Vân Khánh | Hải |
| An Khánh | Vân Khánh (core) |
| Kiên (T3, T4 core code) | Vân Khánh |
| Kiên (T9) | Vân Khánh (short checklist) |
| Hải | Vân Khánh |
| Linh | Vân Khánh (short checklist) |
| Minh | Vân Khánh |

**Backups:** An Khánh for T8a and T8b. Kiên takes over T12a if it slips. T5 falls back to text only (D13).

## 4. Tasks

### 4.1 Lead

**T0a: Shared contracts and stubs** (Vân Khánh, due Fri 06/11). Depends on: nothing.
- Contracts in two files. `src/padding_oracle/core/contracts.py` holds the exact rules the code uses: oracle classes and methods (perfect and noisy, with query counter), word list and split columns, experiment output (CSV) columns. `docs/contracts.md` explains what each part is for, why we chose it, and how to use the fake oracles. If the two disagree, the code is right.
- Stubs, so later tasks can start without waiting: a fake perfect oracle, a fake noisy oracle, the T7 function signature with a dummy body, and a stub attack for the harness.
- Done when: Kiên, Hải, Linh and Minh can code against it without asking.

**T0b: Repo, CI, smoke tests, AI rules file** (Vân Khánh, due Fri 06/11). Depends on: T0a.
- Repo, CI with 3–5 smoke tests (create a block, run the Tier 1 attack on a small case, write an output file), AI rules file, Python version and requirements.

**E1: Explainer sheet** (Vân Khánh, due Fri 13/11). Depends on: the Tier 3 results taking shape.
- One page: what the project does, architecture, who owns which part, 5–6 likely questions with suggested answers. Everyone reads it.

**M1: Final merge and demo build** (Vân Khánh, due Sat 14/11). Depends on: all code tasks.
- Merge, run everything from a clean checkout, fix only blocking problems.

### 4.2 Tier 1 and countermeasures

**T3: AES-CBC, PKCS#7 padding, perfect oracle, query counter** (Kiên). Depends on: T0a.
- 3a (Fri 06/11): AES-CBC encrypt/decrypt and PKCS#7 padding.
- 3b (Sat 07/11): the perfect oracle ("padding OK or wrong") and the query counter, which counts every query.

**T4: Vaudenay attack and 100-block test** (Kiên). Depends on: T3 (start on the T0a fake perfect oracle).
- 4a (Mon 09/11): the attack recovers all 16 bytes of one block.
- 4b (Tue 10/11): over 100 random blocks (1,600 bytes), the 95% confidence interval of the mean queries per byte is checked against ±5% of 128 (D14). Results saved in the T0a format.
- **Check:** the D14 statistics (standard deviation about 74, wobble about ±2.8%) against the measured spread.

**T5: Encrypt-then-MAC and AES-GCM, attack fails** (Minh). Depends on: T3, T4.
- 5a (Mon 09/11): the two server functions (Encrypt-then-MAC with the MAC checked first, AES-GCM with the tag checked first), same rejection every time.
- 5b (Tue 10/11): run the Tier 1 attack against both and show it fails.
- Fallback if late: AES-GCM explained in text only (D13).

**T13: Three-server-type figure** (Minh, due Mon 09/11). Depends on: nothing (table in D13).
- One table or diagram: (1) different error messages = perfect oracle, (2) same message but small timing difference = noisy oracle, (3) MAC or tag checked first = no oracle. No code.

**T13b: Attack diagram, Figure 1** (Linh, due Sat 07/11). Depends on: nothing.
- Diagram of CBC decryption showing the XOR step: the attacker changes the previous ciphertext block, and the padding check tells him when his guess is right.

### 4.3 Word list and Tier 2

**T1: Word list and split** (Minh, due Sat 07/11). Depends on: nothing. Details, exact build steps and the count check: [wordlist-research.md](wordlist-research.md), section 6.

**T2: Read Canvel and check the facts** (An Khánh, due Sat 07/11). Depends on: nothing. Details: [wordlist-research.md](wordlist-research.md), section 6.
- **Check:** in the Canvel PDF (Sec. 4.1, 4.3, 5.2, Table 1, ref [5]): the timing values, C₀ = 31, 166 vs 4,239, the 4–5× gain, what 712,786 counts, which cipher the live test used, whether the secret shared a block with the line ending and the MAC (Sec. 5.2), and whether `Check4` uses the same thresholds τ± for every candidate (our reading).

**T6: Noisy oracle simulator** (Hải, due Sat 07/11). Depends on: T0a.
- Gaussian timing oracle (μ_R ≈ 23.63, μ_W ≈ 21.57, σ ≈ 1.86 as inputs; confirm with the T2 list), query counter, a noise-off mode.

**T7: Canvel sequential test** (Hải, due Tue 10/11). Depends on: T6, T2 list (start on the T0a fake noisy oracle).
- Ordered sequential test in the style of Canvel's `DecryptBlock4`, layout D15.
- Write the Tier 2 setup notes in the T7 PR description.

**T8a: Dictionary attack** (Linh, due Wed 11/11). Depends on: T1, T6, T7 (start on the T7 function signature from T0a).
- Dictionary = all SCOWL eight-letter words, uniform order, layout D15.

**T8b: Tier 2 experiments and pattern checks** (Linh, due Thu 12/11). Depends on: T7, T8a, T1.
- The three pattern checks of D14: dictionary vs random block, sequential test vs simpler method (ratio next to Canvel's 4–5×), noise off gives the same plaintext as Tier 1.

### 4.4 Tier 3

**T9: Trigram prior** (Kiên, due Wed 11/11). Depends on: T1, T0a.
- Reversed trigram with add-k smoothing over 256 byte values, fitted on train words only, k chosen on dev, share of zero-count test trigrams reported (D12).

**T10: Posterior-threshold attack** (An Khánh, due Wed 11/11). Depends on: T6, T2 list, T9.
- Built with a uniform prior first. The T9 prior is plugged in on Thu 12/11.
- The prior is a parameter, so T11 can run the same attack with a uniform prior.
- Accept a candidate when its posterior is above 1 − δ, with **δ = 0.001 per byte (D18)**; one shared posterior; reuse old samples.
- **Check:** that our rule is the posterior form of the Baum–Veeravalli MSPRT (our derivation; read the primary paper).

**T11: NCC and Sequential Halving baselines** (Hải, due Thu 12/11). Depends on: T10, T6.
- NCC's method: run the T10 attack with `prior = uniform`, on the same Gaussian noise. No new decision rule. **Same δ as T10 (D18).**
- Sequential Halving, the extra baseline. Like NCC, it takes `max_queries`, the query budget for the **whole word** (all `n_bytes` bytes). Each byte gets B = `max_queries` ÷ `n_bytes`. It needs B ≥ 2,048 (256 candidates × 8 rounds), so `max_queries` ≥ 16,384 for the 8-byte word; below that it raises an error. Steps, for one byte with n candidates and a byte budget B:
  1. Number of rounds R = ⌈log₂ n⌉.
  2. In each round, query every remaining candidate ⌊B / (|S| · R)⌋ times, where |S| is the number of remaining candidates.
  3. Keep the half with the highest mean timing (correct padding takes longer: μ_R > μ_W). Drop the rest.
  4. After R rounds, one candidate is left: accept it.
- Every round rounds down, so part of B can stay unused (B = 3,000 uses 2,666). The harness records the real `oracle.queries`.
- **Check:** Sequential Halving follows Karnin et al. (2013) (read the primary paper).

**T12a: Evaluation harness** (Minh). Depends on: T0a stub, then T4, T7, T8a.
- 12a-1 (Tue 10/11): harness runs on the stub attack and writes the output file (queries, success rate, error rate, seed).
- 12a-2 (Thu 12/11): plug in the Tier 1 and Tier 2 attacks. The Tier 3 attacks are plugged in by T12b.

**T12b: Tier 3 experiments and charts** (Hải, due Fri 13/11). Depends on: T10, T11, T12a, T9, and the experiment spec.
- Experiment spec (An Khánh, Thu 12/11 morning, half a page): which runs, the query budget grid, the table layout. δ = 0.001 is fixed (D18).
- **Budget unit: queries per word.** Every attack gets `max_queries` = the grid value. Sequential Halving runs only at grid values ≥ 16,384; lower points are skipped for it. The success-rate chart has a log x-axis and uses the measured `queries` column, not the grid value.
- The harness checks that the measured queries per word do not go above the grid value (a run above it means a budget was ignored).
- Run the harness with the spec: compare all methods at the same measured error rate; per band; random-bytes control (expect no gain); "train = test" control; success rate vs query budget chart.
- **Check:** the real error rate when the prior is wrong (random bytes). The error ≤ δ guarantee only holds when the prior and noise model are correct.

### 4.5 Report

Content and order of each part: [report-outline.md](report-outline.md). Text is written before the numbers arrive, with empty result tables; when results come in, only the numbers are filled in and the text is edited.

| Task | Part | Owner | Text ready | Due (with numbers) | Needs |
|---|---|---|---|---|---|
| R1 | Introduction and Research Question, Background | Duy | – | Sat 07/11 | – |
| R2 | Tier 1 and Countermeasures (Countermeasures is written right after the Tier 1 results, but placed after Tier 3 in the report) | Duy | Tue 10/11 | Wed 11/11 | T4, T5, T13 results |
| R3 | Tier 2 | Duy | Thu 12/11 | Fri 13/11 | T7 PR notes, T8b results |
| R4 | Tier 3, first draft, ending with the limits | An Khánh | – | Fri 13/11 | T12b results (fill the table when T12b is merged) |
| R5 | Conclusion (one short paragraph) | Duy | – | Sat 14/11 | R4 |
| R6 | Assembly, abstract, language edit, page check | Duy | – | Sat 14/11 | R1–R5 |

**Check (R1, R2):** the facts marked [CHECK] in [report-notes.md](report-notes.md): Merget et al. 1.83%, CVE-2021-29443, Lucky Thirteen, Boneh-Shoup §9.4 and §9.7, NIST SP 800-38A/D.

If the report runs over the page limit on Sat 14/11, cut Tier 2 first (D16).