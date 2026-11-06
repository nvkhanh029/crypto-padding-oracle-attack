# Report Outline
 
**Project:** Padding Oracle Attacks on AES-CBC. Introduction to Cryptography, group midterm project, USTH. <br>
**Purpose:** what goes into each section of the report, and how many pages it gets. <br>
**Audience:** the report writer and every member who gives input to the report. <br>
**Last updated:** 06/11/2026.
 
Read [report-notes.md](report-notes.md) first for the story and the claims to avoid. Deadline: 15/11/2026, 23:00.
 
---
 
## 1. Rules
 
- English, less than 5 pages, not counting cover, table of contents, table of figures, references and annexes. Plan as if figures count.
- Write in your own words. No AI for report text.
- Facts marked [CHECK] in [report-notes.md](report-notes.md) must be checked in the source before use.
- Use only our own measured numbers for savings. No percentage from the literature.
- Extra tables (seed, split sizes, k grid, per-band results) go to an annex. The main text must stand alone.
- Cover: report title (D8 in [decisions.md](decisions.md)) with the registered title as a small line.
## 2. Sections and page budget (4.75 pages, 0.25 spare)
 
| # | Section | Pages | Task |
|---|---|---|---|
| 0 | Abstract, about 100 words, written last | 0.15 | R6 |
| 1 | Introduction and Research Question | 0.5 | R1 |
| 2 | Background | 0.5 | R1 |
| 3 | Tier 1: Vaudenay | 1.0 | R2 |
| 4 | Tier 2: Canvel | 0.6 | R3 |
| 5 | Tier 3: prior-aware attack | 1.25 | R4 (draft), edited by Duy |
| 6 | Countermeasures | 0.5 | R2 |
| 7 | Conclusion | 0.25 | R5 |
 
- The report goes from the attack (sections 3–5) to how cryptography fixes it (section 6).
- Section 6 is **written early**, right after the Tier 1 results, but it is **placed after section 5** in the report.
- If the report runs long, cut section 4 first. Do not cut Background or Countermeasures.
## 3. What each section contains
 
**0. Abstract.** The problem, what we did, the main result with our own numbers, the message.
 
**1. Introduction and Research Question (0.5).** Why this topic: real attacks on real systems, and "encryption alone is not enough". What we do in 3 tiers. Honest scope: simulation only, "to our knowledge". The research question in one or two sentences at the end (fallback question in [report-notes.md](report-notes.md), section 11).
 
**2. Background (0.5).** AES block cipher, CBC mode, PKCS#7 padding, what an oracle is, Vaudenay's idea. CBC gives confidentiality but not integrity. Figure 1: attack diagram (T13b).
 
**3. Tier 1: Vaudenay (1.0).** Setup. 100 random blocks. The reproduction rule (D14): 95% confidence interval within ±5% of 128; say that 95% and ±5% are conventions we chose and why. One result table: mean queries per byte against 128.
 
**4. Tier 2: Canvel (0.6).** Noisy timing oracle, simulated, with timing inputs from Canvel. SCOWL list (36,322 words). Easy block layout and why. Results checked by pattern (D14). Why our numbers differ from Canvel's: our list is about 20 times smaller.
 
**5. Tier 3: prior-aware attack (1.25).** The three baselines. What is ours and what is NCC 2023 (the posterior-threshold rule is theirs; our part is a non-uniform prior in it, on Canvel's Gaussian timing noise). Trigram prior. Baselines: Tier 2 test, NCC's method, Sequential Halving. Split method. Results at the same error rate, per band. Random-bytes control (expect no gain or a loss). One chart: success rate against query budget. **End with the limits:** when a prior helps and when it does not, easy block layout, American English, simulation only.
 
**6. Countermeasures (0.5).** Why plain CBC is weak. Encrypt-then-MAC and AES-GCM: the attack fails on both. Table of the three server types (T13). Tier 3 does not show that these fixes are insufficient. If Tier 3 is dropped, the "noisy oracle" row of the table points to Tier 2 only.
 
**7. Conclusion (0.25).** One short paragraph, only our own numbers. Encryption alone is not enough; use authenticated encryption. Closing message: padding oracles are fixable, and where a leak remains, a good prior makes the attack cheaper.
 
## 4. How the rubric is covered
 
- Section 3 and the code behind it: the required "implement with tools" level (11+) and the first reproduction (15+).
- Section 4: a second reproduction.
- Section 5: "design, implement, evaluate, analyze" (17+).
- Figure 1, the three-server table and the Tier 3 chart: the "diagram or chart" level.
## 5. Getting input
 
- Notes and results for each part are in the PR description of each task: 5–8 bullets plus results, written by the task owner in their own words (task list: [tasks.md](tasks.md)).
- Duy drafts sections 1–3 and section 6 early, with empty result tables.
- An Khánh writes the first draft of section 5; Duy edits it so the voice is the same throughout.
- Each owner reads the final paragraph about their part and can explain it.