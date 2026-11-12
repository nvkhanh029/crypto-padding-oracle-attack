# Canvel et al. (2003): Facts Checked (T2)

**Project:** Padding Oracle Attacks on AES-CBC. Introduction to Cryptography, group midterm project, USTH. <br>
**Purpose:** every Canvel fact the project uses, checked against the paper, with where it is and what setup it belongs to. <br>
**Audience:** Tier 2 owner (Hải), Tier 3 owners, report writer (Duy). <br>
**Owner:** An Khánh (T2). **Last updated:** 12/11/2026.

**Source read:** B. Canvel, A. Hiltgen, S. Vaudenay, M. Vuagnoux, "Password Interception in a SSL/TLS Channel", CRYPTO 2003, LNCS 2729, pp. 581–597 (the published version, as in the IACR PDF). **Page numbers below are from this version.** Every fact was first read in the author copy on EPFL Infoscience (`CHVV03.ps`, 26/05/2003), then checked again against the published text; the two agree on every fact below.

Status: **OK** = the paper says this. **Our reading** = the paper does not say it in words, but it follows from the paper.

## 1. Numbers

| # | Fact we use | What the paper says | Where | Status |
|---|---|---|---|---|
| F1 | μ_R ≈ 23.63, μ_W ≈ 21.57 | Mean server answer time for a MAC error (padding right) and a padding error (padding wrong). | Sec. 2.2, p. 585 | OK |
| F2 | σ ≈ 1.86 | The two spreads are **different**: σ_R ≈ 1.48, σ_W ≈ 1.86. The paper then **takes σ = σ_W ≈ 1.86 for both** (Conjecture 1: two normal distributions with the same σ). | Sec. 2.1 (Conj. 1), Sec. 2.2, pp. 584–585 | OK. Using 1.86 for both is Canvel's own simplification |
| F3 | Unit of the timing values | The text gives no unit, but the x-axis of Fig. 3 is labelled **"Time (in 1/1000s)"**, so the values are in **milliseconds** (axis 18–32 ms; y-axis = number of `decryption_failed` and `bad_mac_error` messages). Measured on a LAN, through two switches and a Linux PC firewall. | Fig. 3, p. 586; Sec. 2.2, footnote 6 | OK: the unit is ms (1/1000 s) |
| F4 | Outlier cut B | Answers longer than B are ignored (query repeated). Table 1 uses the heuristic value B = 32.93. | Sec. 2.1, Fig. 4–5, Table 1 caption | New fact, optional for T6/T7 |
| F5 | C₀ = 31 | C₀ = average number of candidate trials per block (sum over the b bytes), for the dictionary ordered by probability. They **computed** 31 and then **confirmed** it with an implementation of DecryptBlock4. The best possible is ⌈log₂ D⌉ = 20 yes/no questions, so the overhead is 11. | Sec. 4.2 (definition), Sec. 4.3, pp. 591–592 | OK |
| F6 | C₀ for a random block | Uniform bytes: C₀ = b(\|Z\|−1)/2 + b, so 1028 for \|Z\| = 256 and b = 8. | Sec. 4.2, Table 1 | OK |
| F7 | 166 vs 4,239 | Complexity C for success probability p = 50%: **166** with the dictionary, **4,239** for a fully random block (\|Z\| = 256). C counts oracle queries, and each query needs a new SSL/TLS session (Sec. 5.1 calls it "166 sessions"). These are **calculated** values (formula (5); Table 1 caption: "Calculated complexity"), not measured counts. | Sec. 4.3, Table 1, Sec. 5.1 | OK: say "calculated", not "measured" |
| F8 | Full Table 1 | Dictionary: C = 166, 181, 199, 223, 261, 380 for p = 0.5, 0.6, 0.7, 0.8, 0.9, 0.99. Uniform 256: 4239 … 11335. Also \|Z\| = 128 (C₀ = 516) and \|Z\| = 64 (C₀ = 260). Each column also gives log τ₋ and log τ₊. | Table 1, p. 593 | OK, recomputed (section 3); one likely typo |
| F9 | "4–5×" | Gain of the **sequential** test (DecryptBlock4 with STOP/ACCEPT) over the **fixed-n** test (DecryptBlock2), found by a "similar computation", not by an experiment. It is **not** 4,239 / 166 (≈ 25.5). | Sec. 4.3, last paragraph | OK (matches decisions.md §7) |
| F10 | 712,786 | They took the word list [5] and kept **only the words of 8 characters** (b = 8 bytes): 712,786 words. The paper calls them "words"; it does not say why the count is so large. The number is printed with a Swiss thousands mark (712'786), which copy-paste can turn into "7120786"; the ⌈log₂ D⌉ = 20 in the same paragraph confirms 712,786 (2²⁰ ≈ 1.05 million, while 7.1 million would need 23). | Sec. 4.3, p. 592 | OK: write "an 8-character subset of a large word list" |
| F11 | "Less than an hour" | Abstract and Sec. 7. With 5 IMAP folders and a check every 5 minutes, Outlook gives 60 sessions per hour; with a check every minute, 166 sessions take about half an hour. | Abstract, Sec. 5.1, Sec. 7 | OK |

## 2. Setup facts

| # | Question | Answer from the paper | Where | Status |
|---|---|---|---|---|
| S1 | Why 8-letter words? | Because the block length is b = 8 bytes (DES/3DES), so one 8-character password fills exactly one block. | Sec. 1.1 (b = 8 for DES), Sec. 4.3 | OK. Our AES block is 16 bytes, hence the 8-byte prefix + 8-letter word layout (D15) |
| S2 | Which cipher in the live test? | **Not named exactly.** Outlook used RC4-MD5 by default, so they forced the IMAP server to offer **only CBC block ciphers**. The text mentions 3DES_EDE_CBC_SHA as the suite the standards say should be supported, and the example uses an 8-byte block. **AES is never mentioned.** | Sec. 1.1, Sec. 5.2, footnote 10 | OK: write "an 8-byte CBC block cipher (likely 3DES)" |
| S3 | Live setup | Outlook Express 6 on Windows XP, an IMAP4 server, TLS through stunnel 3.22, man-in-the-middle by DNS spoofing, all on a LAN. OpenSSL 0.9.6d already sent the same error message for both errors, but the timing difference was still there. | Sec. 5.1, Sec. 5.2 | OK |
| S4 | Did the secret share a block with the line ending and the MAC? | **Yes, sometimes.** The last bytes of the password can fall in the first MAC block; then those bytes cannot be recovered. Example with a 4-letter user name: the last 3 password characters share a block with `"`, CR LF and the HMAC. | Sec. 5.2 | OK: our D15 layout is the easy case |
| S5 | Same thresholds τ± for every candidate? | `Check4` (Fig. 5) takes only the tested string u; nothing in it depends on the candidate's probability. Table 1 gives **one** pair (log τ₋, log τ₊) per success target p, computed from C₀, b and p only (formulas (6)–(7)). So yes, the same τ± for every candidate and every byte. | Fig. 5, Sec. 4.2 (6)–(7), Table 1 | Our reading, now well supported (no sentence states it directly) |
| S6 | How is the prior used? | Only in **step 1 of DecryptByte4**: sort the candidates by decreasing probability. The STOP/ACCEPT test does not use it. | Sec. 4.1, Fig. 5 | OK: this is the gap of D2 (prior also in the decision rule) |
| S7 | Backtracking? | **None.** DecryptByte4 repeats the loop over all candidates until one is accepted; a wrong byte is never revisited. Their analysis even uses a weaker version where a wrong ACCEPT just means failure. | Fig. 5, Sec. 3.2 | OK (matches decisions.md §7) |
| S8 | What is reference [5]? | Only "English Word List, Elcomsoft Co. Ltd.", with the company homepage. No version, size or file name. | References, [5] | OK: cannot be rebuilt |

## 3. Formulas Tier 2 can reuse (T7)

All under Conjecture 1 (normal, same σ), Sec. 2.3–2.4 and Sec. 4.2:

- STOP when S_j = (T₁ + … + T_j) − j·(μ_R + μ_W)/2 leaves the interval [τ′₋, τ′₊]; ACCEPT (padding right) if S_j > τ′₊. Eq. (1)–(2).
- τ′± = σ² / (μ_R − μ_W) · log τ±. Eq. (3)–(4).
- Wald approximation: τ₊ ≈ (1 − ε₋)/ε₊, τ₋ ≈ ε₋/(1 − ε₊), where ε₊ = false accept of a wrong candidate, ε₋ = false reject of the right one.
- Expected samples: J_W ≈ −2σ²/(μ_R − μ_W)² · log τ₋ (wrong candidate), J_R ≈ 2σ²/(μ_R − μ_W)² · log τ₊ (right candidate).
- Given a target p: log τ₊ ≈ log C₀ + log(C₀ − b) − log b − log log(1/p); log τ₋ ≈ log(C₀ − b) − log C₀ − log b + log log(1/p). Eq. (6)–(7). The logs are **natural** logs.
- Complexity: C ≈ 2σ²/(μ_R − μ_W)² · (C₀ log C₀ − (C₀ − 2b) log((C₀ − b)/b) − C₀ log log(1/p)). Eq. (5).

**Recomputed:** a short Python script with formulas (5)–(7) and μ_R = 23.63, μ_W = 21.57, σ = 1.86, b = 8 gives all of Table 1 (C, log τ₋, log τ₊ for the four C₀ values and six p values) within ±1 on C and ±0.01 on the logs (rounding), except one cell: \|Z\| = 128, p = 0.6, where the formula gives C ≈ 2436 and the paper prints **2346** (very likely swapped digits in the paper). So 166 and 4,239 come straight from formula (5).
