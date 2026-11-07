# Notes for the Report Writer
 
**Project:** Padding Oracle Attacks on AES-CBC. Introduction to Cryptography, group midterm project, USTH. <br>
**Purpose:** the story of the report. Why this topic, why a noisy oracle, what "Countermeasures" means, what each tier proves, how we judge a reproduction, why we use the easy block layout, where the cryptography is in the report, the report structure and page budget, and what we must not claim. <br>
**Audience:** the report writer and every member who writes or checks a part of the report. <br>
**Last updated:** 05/11/2026.
 
## Contents
 
0. [Read this first](#0-read-this-first)
1. [Why did we choose the padding oracle attack?](#1-why-did-we-choose-the-padding-oracle-attack)
2. [Why do we focus on a noisy oracle?](#2-why-do-we-focus-on-a-noisy-oracle)
3. [The noisy oracle is NOT the "Countermeasures" part](#3-the-noisy-oracle-is-not-the-countermeasures-part)
4. [What are Encrypt-then-MAC and AES-GCM?](#4-what-are-encrypt-then-mac-and-aes-gcm)
5. [We do not research new countermeasures](#5-we-do-not-research-new-countermeasures)
6. [Tier 3 does NOT prove the countermeasures are insufficient](#6-tier-3-does-not-prove-the-countermeasures-are-insufficient)
7. [What is the meaning of the research?](#7-what-is-the-meaning-of-the-research)
8. [What "reproduction" means, and how we use each source](#8-what-reproduction-means-and-how-we-use-each-source)
9. [What Tier 2 means](#9-what-tier-2-means)
10. [Why we use the easy block layout](#10-why-we-use-the-easy-block-layout)
11. [Where the cryptography is in our report, and the report structure](#11-where-the-cryptography-is-in-our-report-and-the-report-structure)
12. [Checklist before writing](#12-checklist-before-writing)
13. [Sources](#13-sources)
---
 
## 0. Read this first
 
- This is a **planning and explainer note**. It is **not** report text.
- The report must be written by the team, **not by AI**. Read this note, understand the ideas, then write your own sentences. Do not copy from here.
- Facts marked **[CHECK]** have not been verified against the original source. Open the source before you put the fact in the report.
- Facts marked **[OUR REASONING]** are our own argument, not a published result. You may use the idea, but do not present it as a fact from a paper.
- Decision numbers (D1, D13, ...) and the numbers to reproduce are in [decisions.md](decisions.md).
---
 
## 1. Why did we choose the padding oracle attack?
 
The report should explain this early, in the introduction. There are two kinds of reasons. Put the first kind in the report. The second kind is only for us.
 
**Reasons for the report (why the topic is worth studying):**
 
1. **It is a real attack on real systems.** Padding oracles have broken real protocols and libraries: SSL/TLS (Canvel et al. 2003), Lucky Thirteen on TLS and DTLS (AlFardan and Paterson 2013), and the `jose` npm library (CVE-2021-29443). A 2019 scan found 1.83% of the Alexa Top 1M sites still vulnerable (Merget et al. 2019). **[CHECK all four before citing.]**
2. **It teaches a key lesson of the course: encryption alone is not enough.** CBC hides the message but does not detect changes. A tiny leak (one bit: "padding OK or not") is enough to recover the whole plaintext. This is why modern systems use authenticated encryption (Encrypt-then-MAC, AES-GCM).
3. **It fits all levels of the rubric.** We can describe it (What), explain why it matters (Why), implement it in code (How, required), reproduce published numbers (15+), and evaluate a small improvement (17+).
4. **There are clear published numbers to compare with.** Vaudenay (2002) gives about 128 queries per byte with a perfect oracle, and Canvel et al. (2003) give timing values and session counts. This makes a real reproduction possible.
**Reasons only for us (do not lead with these in the report):**
 
- Low tool risk: pure Python, no special hardware or network setup.
- It fits the time we have (deadline 15/11) and the 5-page limit.
You may mention in one short phrase that the attack can be simulated fully in software, which makes the results repeatable. That is a fair method reason.
 
---
 
## 2. Why do we focus on a noisy oracle?
 
**First, what is an oracle?** In a padding oracle attack, the attacker sends a modified ciphertext to the server. The server reacts in a way that tells the attacker whether the padding was correct. That reaction is the "oracle".
 
- **Perfect oracle:** the server always tells the truth, "padding OK" or "padding wrong". Vaudenay (2002) already solved this case. The result is predictable: about 128 queries per byte on average. There is nothing new to find here. We only reproduce it (Tier 1).
- **Noisy oracle:** the answer is sometimes wrong or unclear. The attacker must ask the same question many times and decide when he is sure enough. This is where a smart guess about the plaintext (a *prior*, for example "English words are more likely than random bytes") can save queries.
**Why we chose it** (D2, D3):
 
1. **A small but real gap.** "Try likely bytes first" was already done by Canvel et al. (2003). Our gap is narrower: use the prior *both* to order the candidates *and* to decide when to accept one, on a noisy oracle.
2. **A fair comparison.** NCC Group's 2023 method uses the same decision rule (stop when the top posterior is high enough) but with a **uniform** prior. So the only difference between their method and ours is the prior.
3. **Repeatable.** We simulate the noise, so results are repeatable and do not depend on a real network.
**Does the real web have noisy oracles?** Yes, in two kinds:
 
- **Clear oracle (not noisy):** the server shows a different error message or behaviour. Merget et al. (2019) scanned for this. **[CHECK]**
- **Noisy oracle (timing):** both cases look the same, and the only clue is a small time difference. Canvel et al. (2003) did this on SSL/TLS. In their numbers (mean time when padding is right about 23.63, wrong about 21.57, standard deviation about 1.86), the gap between the two cases is about the same size as the noise, so one query is not enough. **[CHECK: open the PDF before using these numbers.]**
**Honest limit:** our noise is **simulated**. We do not claim we measured a real server. A safe idea for the report: the noise model is based on the timing numbers reported by Canvel et al.
 
---
 
## 3. The noisy oracle is NOT the "Countermeasures" part
 
This is easy to confuse, so be clear about it.
 
The registered title is *Padding Oracle Attacks on CBC Mode: Reproduction and Countermeasures*. How our work maps to it:
 
| Part of the title | What we do | Tier |
|---|---|---|
| Reproduction | Vaudenay (2002) with a perfect oracle, then Canvel et al. (2003) with a noisy timing oracle | 1 and 2 |
| Countermeasures | Encrypt-then-MAC and AES-GCM; show that the attack fails against them | 1 (about half a page, D13) |
| Not in the registered title | Prior-aware attack on a noisy oracle | 3 |
 
So the noisy oracle belongs to the **attack** side.
 
This is why D8 has two titles. The registered title is the safe one. The report title says what we really do. If Tier 3 fails, the report title switches back to the registered one, and Tiers 1 and 2 still fit it.
 
**Do not write** that "adding noise or random delay" is a countermeasure. We have no verified source for that idea.
 
---
 
## 4. What are Encrypt-then-MAC and AES-GCM?
 
Both fixes do the same thing: the server **checks that the ciphertext was not changed, before it decrypts anything**. The attacker's fake ciphertexts are rejected at once, and he learns nothing from padding errors.
 
**Why plain CBC is weak:** CBC only hides the message. It does not detect changes. The attacker edits the ciphertext, the server decrypts it, and the server's reaction leaks information.
 
### 4.1 Encrypt-then-MAC
 
- A **MAC** is a short tag computed from data plus a secret key. If one bit of the data changes, the tag no longer matches.
- Sender: (1) encrypt with CBC, (2) compute the MAC over the **ciphertext**, (3) send both.
- Receiver: (1) check the MAC first, (2) if wrong, reject with the same error every time, (3) only if right, decrypt.
- The padding is never looked at for a modified ciphertext, so the oracle disappears.
A picture to explain it: a sealed envelope with a signature on the **outside**. The receiver checks the signature before opening. If the signature is wrong, the envelope is never opened.
 
**Order matters.** Older TLS used MAC-then-encrypt: the MAC was checked only *after* decrypting and removing padding, so padding errors could still leak. Usual advice is also to use two separate keys, one for encryption and one for the MAC. **[CHECK in Boneh-Shoup §9.4 and Bellare-Namprempre.]**
 
### 4.2 AES-GCM
 
- One mode that does **encryption and authentication together**. It outputs ciphertext plus an authentication tag.
- It is based on counter mode, so there is **no padding at all**. No padding means no padding oracle.
- The receiver checks the tag first and releases the plaintext only if the tag is correct.
- Important rule: never reuse the same nonce with the same key. GCM breaks badly if you do.
- **[CHECK in Boneh-Shoup §9.7 and NIST SP 800-38D.]**
### 4.3 What the report shows (D13)
 
- The attack works on plain CBC, and fails on Encrypt-then-MAC and on AES-GCM, because the server gives the same rejection every time. Both fixes are in code. If Tier 1 runs late, AES-GCM is explained in text only.
- **One table or diagram of three server types** links the parts of the report; the report-ready diagram is [server-types.svg](../figures/server-types.svg):
| Server type | What the attacker sees | Oracle | Where in our work |
|---|---|---|---|
| 1. Different error messages (plain CBC) | Clear "padding OK / wrong" | Perfect | Tier 1 |
| 2. Same message, but time differs a little | Small time gap plus noise | Noisy | Tiers 2 and 3 |
| 3. MAC or tag checked first | Same rejection, same work | None | The fix |
 
Keep the whole section to about half a page, including the table. Plan as if figures count toward the 5-page limit.
 
**Real-world example:** CVE-2021-29443 in the `jose` npm package was a real padding-oracle bug, fixed by checking the HMAC before decrypting. **[CHECK the advisory before citing.]**
 
---
 
## 5. We do not research new countermeasures
 
In cryptography, attack research and defense research often go together. But here the countermeasure is **already known and solved** (Encrypt-then-MAC, AES-GCM). So we do not try to improve it. Reasons:
 
- The rubric's top level, "design an algorithm, implement, evaluate, analyze" (17+), is covered by Tier 3, which improves the **attack**.
- D9: three tiers, no new scope. Tier 3 is already the biggest risk.
**How attack and defense connect:** hiding the error message is not enough. If the server shows the same error but the timing differs (server type 2), the attacker still has a noisy oracle. Only "check the MAC first" removes the oracle completely. **[CHECK: our reading of Canvel et al.; confirm in the PDF.]**
 
---
 
## 6. Tier 3 does NOT prove the countermeasures are insufficient
 
This is the most important point for the writer, because it is easy to get wrong.
 
- Encrypt-then-MAC and AES-GCM **are** sufficient. If the server checks the MAC first, there is no oracle, and our attack, including Tier 3, gets nothing.
- Tier 3 asks one narrow question (research question in [decisions.md](decisions.md), section 2): **if an oracle still exists but is noisy, how many queries can a prior save?** It is a small, measured improvement in simulation, not a new attack and not a test of the fixes.
The logic of the report:
 
| Part | Message |
|---|---|
| Tier 1 | Perfect oracle: the attack works. Encrypt-then-MAC and AES-GCM: the attack fails. |
| Tier 2 | Noisy timing oracle: the attack still works (Canvel). |
| Tier 3 | With a noisy oracle, a prior makes the attack cheaper. |
| Countermeasures | Only "check the MAC first" removes the oracle completely. |
 
**Safe to say:** hiding the error message is not a full fix, because a timing difference can still be an oracle. A cheaper attack makes such weak fixes even less safe. **[CHECK in the papers.]**
 
**Do not say:** "Tier 3 proves the current countermeasures are not enough." Our own experiment shows the opposite for Encrypt-then-MAC and AES-GCM.
 
**Word check:** Tier 3 makes the attack **cheaper** (fewer queries). Do not write "more expensive attack".
 
---
 
## 7. What is the meaning of the research?
 
The meaning is **real but modest**. A good countermeasure existing does not mean everyone uses it.
 
1. **Vulnerable systems still exist** (Merget et al. 2019; CVE-2021-29443). **[CHECK both.]**
2. **Partial fixes can leave a noisy oracle.** Same error message but different timing is still an oracle. Tier 3 measures how much a prior helps in that case.
3. **A cheaper attack may fit under a query limit.** If a defender caps the number of queries, an attack that needs fewer queries may stay under the cap. **[OUR REASONING.]** We only plan a chart of "success rate vs query budget Q" for it.
**Be honest in the report:**
 
- We do **not** claim a new attack or a real-world break.
- The result may be **no gain**. On random bytes, expect no gain or even a loss, because the prior is wrong there. Reporting this is a valid result: it shows when a prior helps and when it does not.
- Use "to our knowledge" for any novelty claim.
- NCC Group (2023) already uses a posterior-threshold stopping rule. So "accept when posterior > 1 − δ" is **not our idea**. Our contribution is only (1) a non-uniform prior inside this rule and (2) Canvel's Gaussian timing model. Say this clearly.
- Our block layout is the **easy alignment** (section 10). Our results apply to this layout only.
**Why this is enough for the course:** the rubric asks for "reproduce other works" (15+) and "design, implement, evaluate, analyze" (17+). It does not ask for real-world impact.
 
A possible one-line message for the report (rephrase it in your own words):
 
> Padding oracles are fixable. Where a leak remains, even a noisy one, a good prior makes the attack cheaper, and we measure by how much.
 
---
 
## 8. What "reproduction" means, and how we use each source
 
**Reproduction does not mean the exact same number.** These attacks are random, so even a correct reproduction gives "close to, with some spread". For example, Jüttner (2012) measured a mean of 1048 requests per block against a theory of about 1034.
 
**How we use each source** (full table in [decisions.md](decisions.md), section 5):
 
| Source | How we use it |
|---|---|
| Vaudenay 2002 | Tier 1 main check: our mean queries per byte vs about 128 |
| Jüttner 2012 | Optional Tier 1 cross-check of the mean and spread (his blocks are 8 bytes, so scale about 2×). Cite only if used, and say it is a bachelor thesis, not peer-reviewed |
| Canvel et al. 2003 | Tier 2: his timing values are **inputs** to our simulation; his results are compared **by pattern only** |
| NCC Group 2023 | Tier 3: their method is our baseline (c), run on our Gaussian noise |
 
**The "close enough" rule (D14):**
 
- **Tier 1** counts as reproduced if, over **100 random blocks (1,600 bytes)**, the **95% confidence interval** of the mean queries per byte lies within **±5% of 128**.
- Why these numbers:
  - **100 runs:** the same as Jüttner, so our spread can be compared with his. 1,600 bytes makes the random wobble small.
  - **95%:** the usual convention in statistics ("the true average is very likely inside this range").
  - **±5%:** for each byte, the correct value is found after 1 to 256 tries, all equally likely. So the mean is about 128 and the spread (standard deviation) about 74. With 1,600 bytes, the expected wobble of the mean is only about ±2.8%. So ±5% lets correct code pass, but still catches real bugs (for example a query counted twice gives +100%). Jüttner's own run was about 1.4% from theory, inside ±5%. **[OUR REASONING: our calculation; the Tier 1 owner re-checks it against the measured spread.]**
  - Small extra effects (the last byte can look valid by accident; the exact uniform mean is 128.5) are much smaller than 5%.
  - Say in the report that 95% and ±5% are **conventions we chose**, with the reasons above, not rules from a source.
- **Tier 2** is checked **by pattern**, with no number threshold, because our dictionary (36,322 words) is about 20 times smaller than Canvel's (an 8-character subset of a large word list, 712,786 words). It counts as reproduced if: (1) the dictionary attack needs clearly fewer sessions than the random block; (2) the sequential test needs fewer queries than the simpler method, with our ratio reported next to Canvel's 4–5×; and (3) with the noise turned off, Tier 2 recovers the same plaintext as Tier 1.
**Two comparisons to keep apart:** Canvel's "4–5×" is the gain of the sequential test over a simpler method. The ratio 4,239 / 166 (about 25.5) is dictionary vs random block. They are different comparisons.
 
---
 
## 9. What Tier 2 means
 
**Why two reproductions?** The rubric needs only one. Tier 2 exists mainly because it is the **bridge to Tier 3**:
 
1. **Safety net (D4).** Each tier gives a complete, submittable result.
2. **Tier 3 is built on Tier 2.** Tier 2 gives the noisy-oracle simulator and baseline (b), Canvel's ordered sequential test. Without it, Tier 3 has nothing to compare with.
3. **Tier 1 cannot do this job.** A perfect oracle has no noise, so there is nothing for a prior to improve.
**Real role of each tier:**
 
| Tier | Real role |
|---|---|
| 1 | The solid reproduction, checked by number (D14) |
| 2 | Baseline for Tier 3, plus a second reproduction checked by pattern only |
| 3 | Our own measured improvement |
 
**Tier 1 cannot prove the Tier 2 pattern.** It only checks the shared base:
 
| Check | Does Tier 1 help? |
|---|---|
| AES-CBC code, padding, query counting are correct | Yes |
| The noise model (Gaussian timing) is right | No, Tier 1 has no noise |
| The sequential test works like Canvel's | No, Tier 1 does not use it |
| A dictionary attack needs fewer sessions than a random block | No, Tier 1 has no dictionary |
 
That is why D14 adds the noise-off test and the pattern checks for Tier 2.
 
**If Tier 3 fails, Tier 2 still has value:**
 
- **The second paper.** The report title names "Vaudenay and Canvel". Without Tier 2, Canvel is only cited, not reproduced.
- **A more realistic setting.** Tier 1 is a textbook perfect oracle. Tier 2 shows the attack when the leak is only a small timing gap (server type 2). This also supports the countermeasures story: hiding the error message is not enough.
- **A fuller report:** a second experiment and a dictionary-vs-random comparison.
But Tier 2 does **not** secure 15+ by itself (Tier 1 does that), and it does **not** reach 17+ (that needs Tier 3).
 
| If Tier 3 fails | What we still have | Likely level **[OUR REASONING; the lecturer grades]** |
|---|---|---|
| Tier 1 only | One solid reproduction + countermeasures | 15+ |
| Tier 1 + 2 | Two papers, one checked by number and one by pattern | 15+, a stronger report |
| Tier 1 + 2 + 3 | Plus our own measured improvement | 17+ possible |
 
---
 
## 10. Why we use the easy block layout
 
**What we do (D15).** The 16-byte AES block holds a known 8-byte prefix in bytes 1–8 and the 8-letter secret word in bytes 9–16. The attack recovers bytes from the last to the first, so it reaches the word first.
 
**This is a test setup, not a security choice.** We play the attacker. The secret word is invented, so we can measure whether the attack recovers it and how many queries it needs.
 
**Reasons to explain in the report (rephrase in your own words):**
 
1. **Our question is about the prior.** We ask whether an "English word" guess saves queries. The easy layout tests this directly.
2. **The extra unknown bytes cannot help the prior.** In a harder layout, 8 unknown bytes sit to the right of the word. They look random to the attacker, so the prior says nothing about them. They only add a cost that has nothing to do with our question. **[OUR REASONING.]**
3. **Honest limit.** A real system may be harder. For example, in Canvel's test the secret shared a block with the line ending and the MAC. **[CHECK in the PDF, Sec. 5.2.]** Our results apply to this easy alignment only. Say so in the report.
---
 
## 11. Where the cryptography is in our report, and the report structure
 
**Main message.** The attack never breaks AES. It uses a gap in how cryptography is applied: CBC gives **confidentiality** (it hides the message) but not **integrity** (it does not detect changes). So cryptography is on both sides of the report:
 
| Side | What it is | Where |
|---|---|---|
| Attack | Cryptanalysis: we attack AES-CBC, using how CBC decryption works | Tiers 1–3 |
| Countermeasures | Cryptography applied correctly: authenticated encryption (Encrypt-then-MAC, AES-GCM) | Countermeasures section |
 
**The building blocks, and how each one appears in the report:**
 
| Building block | What to explain | How we show it |
|---|---|---|
| AES | A block cipher: encrypts one 16-byte block with a secret key. We use it; we never break it | Short description (Background) |
| CBC mode | Each plaintext block is XORed with the previous ciphertext block (the first one with an IV) before encryption. Decryption: P_i = Decrypt_K(C_i) XOR C_(i−1) | CBC decryption diagram (Background) + our code |
| PKCS#7 padding | Fills the last block to 16 bytes; each padding byte holds the padding length. The server checks it after decryption, and this check is the oracle | Short description (Background) + our code |
| Confidentiality vs integrity | CBC hides the message but does not detect changes | One or two sentences (Background), repeated in the conclusion |
| MAC, Encrypt-then-MAC | A MAC adds integrity; checking it before decrypting removes the oracle | Section 4 of this note + our code |
| AES-GCM | Authenticated encryption: counter mode (no padding) plus a tag | Section 4 of this note + our code |
 
**Why the CBC formula matters.** The attacker changes C_(i−1), and this changes P_i in a way he controls. The padding check tells him when his change gives valid padding. This one line links the background to the attack, so the diagram should show the XOR step clearly. **[CHECK the CBC definition in NIST SP 800-38A and the padding attack in Boneh-Shoup §9.4.2–9.4.3.]**
 
**Report structure and page budget (D16).** Plan as if figures count toward the 5-page limit.
 
| Part | Content | Pages |
|---|---|---|
| Abstract | About 100 words: the problem, what we did, the main result (our measured numbers), the message. Write it last | 0.15 |
| Introduction and Research Question | Why this topic (section 1, report reasons only), then the research question in one or two sentences | 0.5 |
| Background | AES, CBC, PKCS#7 padding, CBC decryption diagram; CBC gives confidentiality, not integrity | 0.5 |
| Tier 1 | Vaudenay reproduction, perfect oracle, D14 check | 1.0 |
| Tier 2 | Canvel reproduction, noisy timing oracle, pattern check | 0.6 |
| Tier 3 | Prior-aware attack, comparison with the baselines, then the limits: when a prior helps, easy block layout, American English, simulation | 1.25 |
| Countermeasures | Encrypt-then-MAC, AES-GCM, the three-server table | 0.5 |
| Conclusion | One short paragraph: encryption alone is not enough; use authenticated encryption | 0.25 |
| **Total** | | **4.75** |
 
- The report goes from the attack (Tiers 1–3) to how cryptography fixes it (Countermeasures). Write the Countermeasures section early, right after the Tier 1 results, even though it comes after Tier 3 in the report.
- If Tier 3 is dropped, the "noisy oracle" row of the three-server table points to Tier 2 only. Countermeasures does not need Tier 3.
- If the report runs long, cut Tier 2 first. Do not cut Background or Countermeasures.
- Extra tables and plots go into the annexes, which do not count toward the limit.
**Research question in the report.** The full question is in [decisions.md](decisions.md), section 2. In the introduction, state it in one or two sentences, and name the three baselines in the Tier 3 part. If Tier 3 fails, use a reproduction question instead, for example: *Can we reproduce Vaudenay's and Canvel's results on AES-CBC, and do Encrypt-then-MAC and AES-GCM stop the attack?* The report title then also switches back to the registered one (D8).
 
---
 
## 12. Checklist before writing
 
- [ ] Open the Canvel PDF (Sec. 4.1, 4.3, 5.2, Table 1, reference [5]) and check every number we use.
- [ ] Open Boneh-Shoup §9.4.1, §9.4.2–9.4.3, §9.7 and check the Encrypt-then-MAC and GCM explanations.
- [ ] Check Merget et al. (2019) for the 1.83% figure, the CVE-2021-29443 advisory, and Lucky Thirteen.
- [ ] Explain in the introduction why we chose this topic (section 1), using the report reasons only.
- [ ] State the research question in one or two sentences at the end of the introduction; use the fallback question if Tier 3 fails (section 11).
- [ ] Explain AES, CBC and padding in the Background before the attack, with the CBC decryption diagram (section 11).
- [ ] Write the abstract last, about 100 words, with our own measured numbers.
- [ ] Do not write that Tier 3 disproves the countermeasures.
- [ ] Do not write "noise or random delay" as a countermeasure.
- [ ] Use only our own measured numbers for savings. Do not quote any percentage of savings from the literature.
- [ ] State the D14 rule and its reasons; say 95% and ±5% are our chosen conventions.
- [ ] Explain why our Tier 2 numbers differ from Canvel's (smaller dictionary).
- [ ] State that our block layout is the easy case, and why (section 10).
- [ ] Keep the countermeasures section, with the three-server table, to about half a page.
- [ ] Check the page budget (section 11): the main text stays under 5 pages, figures included.
## 13. Sources
 
Full list in [decisions.md](decisions.md), section 6.
 
- Vaudenay (2002), Canvel et al. (2003), NCC Group / Sohl (2023): core attack papers.
- Jüttner (2012): optional Tier 1 cross-check; bachelor thesis, not peer-reviewed.
- Boneh and Shoup, *A Graduate Course in Applied Cryptography*: §9.4.1, §9.4.2–9.4.3, §9.7.
- Bellare and Namprempre (2008); NIST SP 800-38A and 800-38D.
- Merget et al. (2019); CVE-2021-29443 advisory.
- AlFardan and Paterson (2013), Lucky Thirteen.