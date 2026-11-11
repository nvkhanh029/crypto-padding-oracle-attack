# Decisions and Direction

**Project:** Padding Oracle Attacks on AES-CBC. Introduction to Cryptography, group midterm project, USTH. <br>
**Purpose:** what we decided, why, what we will build, and which sources we use. When a decision changes, this file is updated. <br>
**Audience:** all team members. <br>
**Last updated:** 11/11/2026. **Deadline:** 15/11/2026.

> The report itself must be written by the team, not by AI. This file is a planning document only. For the story of the report (why this topic, why a noisy oracle, what "Countermeasures" means, what each tier means, where the cryptography is, the report structure), see [report-notes.md](report-notes.md). Every Canvel fact we use, with its page in the paper: [canvel-fact-check.md](canvel-fact-check.md).

## Contents

1. [Decisions](#1-decisions)
2. [Research question](#2-research-question)
3. [Plan by tier](#3-plan-by-tier)
4. [Out of scope](#4-out-of-scope)
5. [Numbers to reproduce](#5-numbers-to-reproduce)
6. [References](#6-references)
7. [Known limits and unverified items](#7-known-limits-and-unverified-items)

---

## 1. Decisions

| # | Decision | Date | Why |
|---|---|---|---|
| D1 | Topic: **Padding Oracle Attack** | 02/11 | Only topic with clear published numbers to reproduce; low tool risk; pure Python. |
| D2 | Direction: **prior-aware attack on a noisy padding oracle** (not plain "try frequent bytes first") | 02/11 | "Try likely bytes first" was already done by Canvel et al. (2003). With a perfect oracle the result is predictable. A noisy oracle plus a prior in the *decision rule* is a narrow but real gap. |
| D3 | Noisy oracle is **simulated** (Gaussian timing or random FP/FN), not real network timing | 02/11 | Real timing needs many days of tuning. Simulation is controlled and repeatable. |
| D4 | Work in **tiers**. Each tier must produce a complete, submittable result | 02/11 | Protects the 15+ target if later tiers fail. |
| D5 | The rubric's circled star = **must have code** (Middle row, "Implement with tools") | 02/11 | Confirmed by Vân Khánh. |
| D6 | No live presentation or Q&A. Report submitted online | 02/11 | Confirmed by Vân Khánh. |
| D7 | Do **not** use leaked password datasets. Use public English word lists | 02/11 | Ethics and legal risk. |
| D8 | Two titles. **Registered:** *Padding Oracle Attacks on CBC Mode: Reproduction and Countermeasures*. **Report:** *Padding Oracle Attacks on AES-CBC: Reproducing Vaudenay and Canvel, and Evaluating a Prior-Aware Attack on Noisy Oracles* | 02/11 | The registered title is the safe one. The report title says what we really do. Put the registered title as a small line on the cover page. If Tier 3 fails, switch the report title to the registered one. |
| D9 | Deadline: **15/11**. Keep the 3 tiers and the out-of-scope list. The last 3 days before the deadline are buffer for Tier 3 and report writing | 02/11 | Tier 3 is the biggest risk. More scope would add risk, not value. |
| D10 | Tier 3 method: **keep the posterior-threshold rule**; add **Sequential Halving** as one extra baseline; prior = **character trigram with add-k smoothing** over the 256 byte values. Newer bandit methods (top-two Thompson sampling, LUCB, Track-and-Stop) are out of scope | 02/11 | Research of 02/11 found no newer method that clearly beats our rule. We derive that it matches the Bayesian multi-hypothesis sequential test (Baum–Veeravalli 1994), so it is defensible. Bandit methods add risk and explanation cost for little gain. Neural priors are overkill. |
| D11 | Word list for Tier 2 and Tier 3: **SCOWL, size 85 files (`wl85.txt`), American English**, lowercase a–z only. **36,322 eight-letter words.** Details in [wordlist-research.md](wordlist-research.md) | 05/11 | Public list with an MIT-like licence (keep its copyright notice). The files are nested (wl60 ⊂ wl70 ⊂ wl80 ⊂ wl85), so every word has a commonness band (A–D). Counts checked by running code. D7 still holds. |
| D12 | Test method: split **by word**, stratified by the 4 bands. Each band 70% train / 10% dev / 20% test, with a fixed seed written in the report. The trigram prior is fitted on **train words only** (the eight-letter words). Choose k on dev; run the test set once. Test words are weighted **uniformly**. Add one control row, "train = test" (upper bound, leaks the answer). Report results per band as a side analysis | 05/11 | A prior fitted on the test words already knows them, so the saving looks too good. Stratifying gives every band the same 20% test share. The bands let us check whether the gain is smaller for rare words (an assumption to test). Uniform weights = an average over the words in the list, not over what users choose. 70/10/20 is a convention, not a rule from a source. |
| D13 | **Countermeasures section kept, about half a page.** Encrypt-then-MAC and AES-GCM are implemented in code, and the Tier 1 attack is shown to fail on both. Fallback if Tier 1 runs late: AES-GCM explained in text only. The report also has **one table or diagram of three server types**: (1) different error messages = perfect oracle (Tier 1); (2) same message but a small timing difference = noisy oracle (Tiers 2–3); (3) MAC or tag checked first = no oracle (the fix). No new code for this table | 05/11 | The registered title ends with "Countermeasures", so the report needs this part. The table links Tier 1 and Tier 2 (Tier 2 already simulates server type 2), and the rubric's middle "What" level asks for a diagram or chart. Planned as if figures count toward the 5-page limit, because the requirements only exclude the table of figures. |
| D14 | **"Close enough" rule for reproduction.** Tier 1 counts as reproduced if, over **100 random blocks (1,600 bytes)**, the **95% confidence interval** of the mean queries per byte lies within **±5% of 128**. Tier 2 is checked **by pattern**, with no number threshold: (1) the dictionary attack needs clearly fewer sessions than the random block; (2) the sequential test needs fewer queries than the simpler method, with our ratio reported next to Canvel's 4–5×; plus (3) with the noise turned off, Tier 2 recovers the same plaintext as Tier 1 | 05/11 | 100 runs matches Jüttner (2012), so our spread can be compared with his. Per byte, the correct value is found after 1 to 256 tries, equally likely: mean about 128, standard deviation about 74. With 1,600 bytes, the expected random wobble of the mean is about ±3.6 queries (about ±2.8%). So ±5% passes correct code but still catches real bugs (for example a query counted twice = +100%). Jüttner's own run was about 1.4% from theory (1048 vs 1034), inside ±5%. Small extra effects (the last byte can look valid by accident; the exact uniform mean is 128.5) are much smaller than 5%. **95% and ±5% are conventions we chose, not rules from a source.** Tier 2 has no number threshold because our dictionary is about 20 times smaller than Canvel's. |
| D15 | **Block layout for Tier 2 and Tier 3.** The 16-byte AES block holds a known 8-byte prefix (bytes 1–8) and the 8-letter word (bytes 9–16). The attack recovers bytes from last to first, so it reaches the word first and stops after 8 bytes. This is the easy alignment, and the report says so | 05/11 | Our research question is about the prior, and this layout measures it directly. In a harder layout (the word in the left half, 8 unknown bytes to its right), those bytes look random to the attacker, so the prior cannot help there; they only add a cost that has nothing to do with our question (our reasoning). The layout is our own simulation choice, not taken from Canvel. It is a test setup, not a security choice: the secret word is invented to measure the attack. |
| D16 | **Report structure and page budget.** Abstract, about 100 words (0.15 page); Introduction and Research Question (0.5); Background: AES, CBC, PKCS#7 padding, CBC decryption diagram (0.5); Tier 1 (1.0); Tier 2 (0.6); Tier 3 (1.25); Countermeasures (0.5); Conclusion (0.25). **Total 4.75 pages.** The report goes from the attack to how cryptography fixes it. Countermeasures is written right after the Tier 1 results but placed after Tier 3. The Tier 3 section ends with the limits (when a prior helps, easy block layout, American English, simulation), and the conclusion is one short paragraph. The research question is stated in one or two sentences. If Tier 3 fails, it becomes a reproduction question: can we reproduce Vaudenay and Canvel on AES-CBC, and do Encrypt-then-MAC and AES-GCM stop the attack? The noisy-oracle row of the three-server table then points to Tier 2 only. Details in [report-notes.md](report-notes.md), section 11, and [report-outline.md](report-outline.md) | 05/11 | The reader must understand CBC before the attack. Putting Countermeasures last keeps the flow from the attack to the fix; writing it early keeps it safe if Tier 3 runs late. The background also shows where the cryptography is: the attack uses the gap that CBC gives confidentiality but not integrity, and the fix applies authenticated encryption. Research papers usually have an abstract, and stating the research question early shows what we test. 0.25 page is spare; if the report runs long, Tier 2 is cut first, and extra tables and plots go to the annexes. |
| D17 | **AES library: PyCryptodome** (`pycryptodome` in `requirements.txt`), for Tier 1 and the countermeasures. Tier 1 uses its AES in CBC mode; PKCS#7 padding is our own code, so the padding check stays visible and easy to explain. The report names the library in one short phrase in the Tier 1 setup; no comparison of libraries | 11/11 | Confirmed by Vân Khánh. It supports both CBC and GCM (GCM is listed among its AEAD modes, AES only), so T5 can use the same library for AES-GCM. The choice does not change the results: the attack counts oracle queries, and any correct AES gives the same count. Source: [PyCryptodome features](https://pycryptodome-master.readthedocs.io/en/latest/src/features.html) |

**Bands (SCOWL levels, a rough measure of how common a word is, not real frequency):**

| Band | SCOWL sizes | Description | 8-letter words |
|---|---|---|---|
| A | up to 60 | Everyday words, the size of a default spell-checker dictionary | 12,750 |
| B | 61–70 | Less common words, found in a large spell-checker dictionary | 6,747 |
| C | 71–80 | Rarer words, still valid in current usage | 8,331 |
| D | 81–85 | The rarest valid words, often unusual or specialized | 8,494 |

## 2. Research question

> With a noisy padding oracle, how many queries does a Bayesian attack save if it uses a non-uniform prior **both to order candidates and to decide when to accept them**, compared with (a) exhaustive search, (b) Canvel's ordered sequential test, and (c) NCC's Bayesian method with a uniform prior, run on the **same Gaussian timing noise** as our attack?

Baseline (c) is the key comparison: it uses the same posterior-threshold rule as our attack, so the only difference is the prior. This isolates the effect of the prior.

Expected result: savings on structured plaintext (English words, maybe JSON or cookies). On random bytes, expect **no gain or a loss** (the prior is wrong there). Report both cases honestly, and measure the **real success rate**, not only the query count.

In the report, this question is stated in one or two sentences under "Introduction and Research Question", with a fallback question if Tier 3 fails (D16).

## 3. Plan by tier

| Tier | Content | Rubric level | Days (estimate) |
|---|---|---|---|
| 1 | Reproduce Vaudenay (2002) with a perfect oracle on AES-CBC. Measure queries per byte and per block over 100 random blocks (expect about 128 per byte, about 2048 per AES block; pass/fail by D14). Optional cross-check: compare our mean and spread with Jüttner (2012), scaled about 2× for 16-byte blocks; cite him only if we use this. Fix with Encrypt-then-MAC and AES-GCM, and show the attack fails (D13) | 15+ (main reproduction, checked by number, D14) | 1–4 |
| 2 | Reproduce Canvel et al. (2003) `DecryptBlock4` in simulation: Gaussian timing in ms (μ_R ≈ 23.63, μ_W ≈ 21.57, σ ≈ 1.86), dictionary = all SCOWL eight-letter words (D11), uniform order, block layout D15. Compare with Canvel's C₀ = 31 and his calculated 166 vs 4,239 sessions at 50% success (our dictionary is much smaller, so expect different numbers). Also provides the noisy-oracle simulator and baseline (b) for Tier 3 | Baseline for Tier 3; second reproduction, checked by pattern (D14) | 4–6 |
| 3 | Improvement: accept a candidate when its posterior > 1 − δ; keep one shared posterior and reuse old samples. Prior: character trigram with add-k smoothing (remember space and punctuation), fitted on the train split only (D12). The attack recovers bytes right to left (D15), so the prior predicts each letter from the letters to its right (a reversed trigram: a normal trigram fitted on reversed words; checked by the Tier 3 owner). Compare with Tier 2, NCC's method (uniform prior, same Gaussian noise) and Sequential Halving, **at the same error rate** | 17+ | 6–8 |
| + | Only if time: backtracking on wrong bytes; JSON/cookie plaintexts; reproduce NCC numbers (about 500k vs 50k queries at 40% error) | — | — |
| — | Write report, check numbers and references | — | 8–10 |

## 4. Out of scope

- Theoretical bounds (guesswork / active hypothesis testing theory).
- Real timing attacks on old OpenSSL or s2n.
- Leaked password datasets.
- Multiple combined oracles and rate-limit as a separate problem (a "success rate vs query budget Q" chart is enough).
- Calling our work a "new attack". It is a small, measured improvement in simulation.
- Bandit methods (top-two Thompson sampling, LUCB, Track-and-Stop) and neural-network priors (see D10).
- New countermeasure research. The known fixes (D13) remove the oracle completely.
- Harder block layouts, such as the word in the left half with unknown bytes to its right (see D15).

## 5. Numbers to reproduce

All checked against the original papers.

| Source | Number | Setup | What we use it for |
|---|---|---|---|
| Vaudenay 2002 | W/2 trials per byte on average, so about 128 per byte | Perfect oracle | **Tier 1 main check.** Our mean queries per byte is compared with 128 using the D14 rule. |
| Jüttner 2012 | Mean 1048 requests per block (range 585–1469, std 199); theory about 1034 | 100 runs, 8-byte blocks (DES). For AES expect about 2× | **Tier 1 optional cross-check** of the mean and the spread (scaled about 2×). Also the reason for 100 runs in D14. Cite only if used; say it is a bachelor thesis, not peer-reviewed. |
| Canvel et al. 2003 | C₀ = 31; 166 sessions (dictionary) vs 4,239 (random block) at 50% success, both **calculated** with Canvel's formula (5), not measured; the sequential test gives a 4–5× gain over DecryptBlock2 | 712,786 eight-character words from an Elcomsoft list; timing in ms: μ_R ≈ 23.63, μ_W ≈ 21.57, σ ≈ 1.86. Canvel measured σ_R ≈ 1.48 and σ_W ≈ 1.86, then used σ = 1.86 for both (his Conjecture 1) | **Tier 2.** The timing values are **inputs** to our simulation. 31, 166, 4,239 and 4–5× are compared **by pattern only** (D14), never as expected values. |
| NCC Group 2023 | About 500,000 queries (exhaustive) vs just over 50,000 (probability-guided) | 16-byte block, 40% error, 0.999 confidence, uniform prior | **Tier 3.** Their method is baseline (c), run on our Gaussian noise. Reproducing their numbers is optional ("+" row) and needs a yes/no flip-noise mode in the simulator. |

Note: Canvel's list is cited only as "English Word List" [5] (Elcomsoft, homepage only) and cannot be rebuilt. Our list has 36,322 eight-letter words, about 20 times fewer, so our Tier 2 numbers will clearly differ. Say so in the report, and do not reuse 31 or 166 as expected values. Page numbers and details for every Canvel number: [canvel-fact-check.md](canvel-fact-check.md).

## 6. References

### 6.1 Core (must read)

1. S. Vaudenay. "Security Flaws Induced by CBC Padding." EUROCRYPT 2002, LNCS 2332. [PDF](https://iacr.org/archive/eurocrypt2002/23320530/cbc02_e02d.pdf)
2. B. Canvel, A. Hiltgen, S. Vaudenay, M. Vuagnoux. "Password Interception in a SSL/TLS Channel." CRYPTO 2003, LNCS 2729, pp. 581–597. [PDF](https://www.iacr.org/archive/crypto2003/27290581/27290581.pdf). Read sections 2–4.
3. E. Sohl (NCC Group). "Exploiting Noisy Oracles with Bayesian Inference." Blog post, 23/06/2023. [Link](https://www.nccgroup.com/research/exploiting-noisy-oracles-with-bayesian-inference/)
4. A. C. Jüttner. Bachelor thesis on padding attacks and CrypTool 2, 2012. Not peer-reviewed. Optional Tier 1 cross-check (D14). [PDF](https://www.cryptool.org/media/publications/theses/BA_Juettner_Padding-Oracle-Attack.pdf)

### 6.2 Stopping-rule theory (for Tiers 2–3 and the explainer sheet)

15. A. Wald. *Sequential Analysis*. Wiley, 1947 (Dover reprint). SPRT and the threshold formulas A = log((1−β)/α), B = log(β/(1−α)).
16. A. Wald, J. Wolfowitz. "Optimum Character of the Sequential Probability Ratio Test." Ann. Math. Statist., 1948. SPRT needs the fewest samples on average for given error rates. (PDF not fetched yet.)
17. TU Berlin course notes on SPRT (easy reading for the team). [Link](https://platform.commit.tu-berlin.de/en/book/fsi/chapter/ch04/section/s01)
18. C. W. Baum, V. V. Veeravalli. "A Sequential Procedure for Multihypothesis Testing." IEEE Trans. Inform. Theory 40, 1994. Multi-hypothesis SPRT (MSPRT); our rule is its posterior form with T = (1−δ)/δ (our derivation, not a quoted theorem). Summary in [arXiv:1310.1844](https://arxiv.org/pdf/1310.1844). (Primary PDF not fetched yet.)
19. Z. Karnin, T. Koren, O. Somekh. "Almost Optimal Exploration in Multi-Armed Bandits." ICML 2013. Sequential Halving (baseline). (Primary PDF not fetched yet.)
20. D. Jurafsky, J. H. Martin. *Speech and Language Processing*, 3rd ed. draft, ch. 3 (n-grams, add-k smoothing; the test set must not overlap the training set). [PDF](https://web.stanford.edu/~jurafsky/slp3/3.pdf). Letter/n-gram counts: [Norvig](https://norvig.com/mayzner.html).
21. S. F. Chen, J. Goodman. "An Empirical Study of Smoothing Techniques for Language Modeling." 1996. Smoothing is tuned on held-out data and reported on a separate part (basis for D12). [PDF](https://arxiv.org/pdf/cmp-lg/9606011)

> **Key idea for the team:** posterior odds = prior odds × likelihood ratio. So "accept when posterior > 1 − δ" is an SPRT whose upper threshold depends on the prior π: LR ≥ (1−δ)/δ × (1−π)/π. A likely candidate needs less evidence.

### 6.3 Data (word list)

22. SCOWL (Spell Checker Oriented Word Lists), size 85 files, American English. Version: GitHub `en-wl/wordlist`, branch `v2`, commit `1e5b7d3` (24/06/2026). SHA-256: filled in by T1. [README (branch `v2`)](https://github.com/en-wl/wordlist/blob/v2/README.md), [repository](https://github.com/en-wl/wordlist)

### 6.4 Context and positioning

5. N. J. AlFardan, K. G. Paterson. "Lucky Thirteen: Breaking the TLS and DTLS Record Protocols." IEEE S&P 2013. [PDF](https://www.isg.rhul.ac.uk/tls/TLStiming.pdf). Section 4.2 *suggests* Markov-chain priors and sequential tests, with no experiments.
6. C. Garman, K. G. Paterson, T. van der Merwe. "Attacks Only Get Better: Password Recovery Attacks Against RC4 in TLS." USENIX Security 2015. [Link](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/garman). Bayesian prior over passwords, for RC4. Note: 2^26 (passwords) vs 2^34 (previous attack, cookies) are different targets.
7. J. Black, H. Urtubia. "Side-Channel Attacks on Symmetric Encryption Schemes: The Case for Authenticated Encryption." USENIX Security 2002. [PDF](https://home.cs.colorado.edu/~jrblack/papers/padding.pdf)
8. R. Merget et al. "Scalable Scanning and Automatic Classification of TLS Padding Oracle Vulnerabilities." USENIX Security 2019. [PDF](https://www.usenix.org/system/files/sec19-merget.pdf). 1.83% of Alexa Top 1M vulnerable.

### 6.5 Fixes (Tier 1)

9. D. Boneh, V. Shoup. *A Graduate Course in Applied Cryptography*, v0.5, 2020. §9.4.1 (Encrypt-then-MAC), §9.4.2–9.4.3 (padding oracles), §9.7 (GCM). [PDF](https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_5.pdf)
10. M. Bellare, C. Namprempre. "Authenticated Encryption: Relations among Notions and Analysis of the Generic Composition Paradigm." J. Cryptology, 2008.
11. NIST SP 800-38A (CBC) and SP 800-38D (GCM).
12. CVE-2021-29443 (`jose` npm): real bug, fixed by checking the HMAC before decrypting. [Advisory](https://github.com/advisories/GHSA-58f5-hfqc-jgch)

### 6.6 Teaching setups (shows our setup is standard)

13. SEED Labs, Padding Oracle Attack Lab (W. Du). [PDF](https://seedsecuritylabs.org/Labs_20.04/Files/Crypto_Padding_Oracle/Crypto_Padding_Oracle.pdf)
14. Cryptopals, Set 3 Challenge 17. [Link](https://cryptopals.com/sets/3/challenges/17)

### 6.7 Block ciphers (Background)

23. C. Paar, J. Pelzl. *Understanding Cryptography*. Springer, 2010. Ch. 4 (AES): p. 87 (AES is used in IPsec, TLS and SSH), p. 89 (128-bit block; 128-, 192- and 256-bit keys). Optional: §3.2, p. 58 (DES: 64-bit block, 56-bit key), only if the report says the attack works on any block cipher in CBC mode. Do not repeat p. 116 (no attack better than brute force): it is out of date since reference 24. Safe wording: "no practical attack on AES is known". Cite only the pages the report uses.
24. A. Bogdanov, D. Khovratovich, C. Rechberger. "Biclique Cryptanalysis of the Full AES." ASIACRYPT 2011. Key recovery on the full AES-128 in about 2^126.1 operations: a little faster than brute force, but not practical. Cite only if the report makes a claim about AES security. [Link](https://eprint.iacr.org/2011/449)

## 7. Known limits and unverified items

- Queries per AES block: about 2048 on average, 4096 in the worst case. With our layout (D15) the attack stops after the 8 word bytes, about 1,024 queries per block with a perfect oracle (our arithmetic).
- That Canvel uses the same thresholds τ± for every candidate is **our reading**, well supported but not stated in one sentence: `Check4` (Fig. 5) takes only the tested string, and Table 1 gives one pair (log τ₋, log τ₊) per success target p.
- Canvel has **no backtracking**: a wrong byte is never revisited (Fig. 5).
- **NCC 2023 already uses a posterior-threshold stopping rule** (stop when the top posterior reaches 0.999) and a probability-guided query order, with a **uniform prior** and yes/no flip noise (FP = FN = 0.4). Checked on 02/11. So "accept when posterior > 1 − δ" is **not our idea**. Our contribution is only: (1) a non-uniform prior inside this rule, and (2) the Gaussian timing model from Canvel. The report must say this clearly.
- The posterior error guarantee (error ≤ δ) only holds if the prior and noise model are correct. With a wrong prior (e.g. random bytes with an English prior) the real error rate can be higher. Measure it, and compare methods only at the same measured error rate. (Checked in T12b.)
- "No one has combined prior + noisy oracle + prior-based decision" is based on our search only. Write "to our knowledge".
- Do not state any percentage of query savings from the literature; none was verified. Use only our own measured numbers.
- **712,786** (Canvel) is the count of 8-character words after filtering the Elcomsoft list, not the size of the whole list. It is far too large for a clean English dictionary, and the paper does not say why. Write "an 8-character subset of a large word list", never "712,786 English words".
- **"4–5×"** is the gain of sequential distinguishers over DecryptBlock2 (Sec. 4.3). It comes from a "similar computation", not an experiment. It is **not** 4,239 / 166 (about 25.5). Keep the two comparisons apart.
- Canvel's analysis uses **8-byte blocks** (DES/3DES) and never mentions AES. The live test forced the server to offer only CBC block ciphers, but the paper does not name the exact one. Write "an 8-byte CBC block cipher (likely 3DES)". Our AES block has 16 bytes (block layout in D15).
- Our block layout (D15) is the **easy alignment**: the word is at the end of the block, with nothing unknown to its right. In Canvel's live test the last password bytes could share a block with the line ending and the MAC, and then could not be recovered (Sec. 5.2). Our results apply to our layout only.
- The D14 statistics (standard deviation about 74, wobble about ±2.8%) are our own calculation. The Tier 1 owner re-checks them against the measured spread. (Checked in T4.)
- That our rule is the posterior form of the Baum–Veeravalli MSPRT is our derivation; the primary paper is not read yet. (Checked in T10.)
- Sequential Halving is taken from Karnin et al. (2013); the primary paper is not read yet. (Checked in T11.)
- Facts marked [CHECK] in [report-notes.md](report-notes.md) (Merget 1.83%, CVE-2021-29443, Lucky Thirteen, Boneh-Shoup §9.4 and §9.7, NIST SP 800-38A/D) are checked before they go into the report. (Checked in R1, R2.)