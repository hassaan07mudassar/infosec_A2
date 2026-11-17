# SmartLock Viva & Demo Cheat Sheet
**Student:** Hassaan Mudassar | **Roll:** 23i-0536 | **Section:** G | **Port:** 9265

Use these exact 2–3 line spoken answers when the instructor asks you about any rubric item during the demo.

---

### Part A.1: Recovered Secrets (10 Marks)

#### 1. Flag Matches Your Instance (4 Marks)
> "My recovered pairing flag is `FLAG{9c9b2d45321061f6}`. It was recovered over the wire by dynamically solving the discrete log of the server's public key, computing the shared secret, and decrypting the captured greeting record."  
> *Run live:* `cd exploits && ./taskA3_solve ../evidence/cap_v1_stream.txt`

#### 2. Recovered DH Exponent Satisfies $g^b \equiv B \pmod p$ (3 Marks)
> "The recovered private exponent is `263367402911`. It mathematically satisfies $2^{263367402911} \pmod{705001380739} = 381871777500$, which exactly matches the public value $B$ sent by the lock in the DH message."

#### 3. Cracked Pairing PIN Matches (2 Marks)
> "The cracked pairing PIN is `sunset625`. I cracked the intercepted MD5 hash `d823a25d5a3ef11f9e1c69a690872def` using a dictionary attack against `pin_wordlist.txt` with a 3-digit mask in under 0.1 seconds."

#### 4. Nonce-Reuse XOR Matches (1 Mark)
> "The recovered nonce XOR hex is `0335282620446c382a3f2d6473180f1e1b2f0410561e`. It is the exact byte-wise XOR of the greeting and status reply ciphertexts ($C_1 \oplus C_2$) sharing the static nonce."

---

### Part A.2: Five-Stage Exploit Demonstrations (22 Marks)

#### 5. Negotiation Downgrade Exploit (4 Marks)
> "The `type:HELLO` offer has no integrity check, and the v1 server accepts the insecure `NULL` suite without signing the transcript. An on-path attacker rewrites the offer to `suites:NULL`, stripping all encryption and exposing all subsequent traffic in cleartext."

#### 6. Authentication Impersonation / MITM (4 Marks)
> "The client never verifies the lock's certificate against a pinned key or CA, and authentication uses an unsalted MD5 PIN hash. An attacker substitutes a rogue RSA public key during the handshake and cracks the weak PIN hash offline to hijack the session."

#### 7. Keying Recovery via Discrete Logarithm (4 Marks)
> "v1 uses an insecure 40-bit prime modulus ($p = 705001380739$), allowing Shanks' Baby-Step Giant-Step to solve the private exponent $b$ in $\mathcal{O}(\sqrt{p}) \approx 8.4 \times 10^5$ operations in 0.1s. Combining $b$ with client value $A$ computes the shared secret and decrypts the flag."

#### 8. Nonce-Reuse Keystream Cancellation (4 Marks)
> "v1 encrypts all AES-GCM records under the identical static IV `1deb1b5c316e24acd9176cde`, creating a two-time pad where $C_1 \oplus C_2 = P_1 \oplus P_2$. By XORing the greeting ciphertext with the known status plaintext, I canceled the keystream and extracted the greeting prefix."

#### 9. Command Replay Exploit (4 Marks)
> "v1 records lack sequence numbers, timestamps, and session binding, so ciphertexts remain static across connections. I intercepted the encrypted `UNLOCK` record from a past session and re-injected it into a new session, causing the lock to accept it and physically open the door."

#### 10. Part A Report Hygiene & Flag Write-Up (2 Marks)
> "All five exploits are mapped to their broken security properties with inline Wireshark captures and terminal logs in Section 2 of my report. Every secret was dynamically parsed from wire streams rather than hardcoded."

---

### Part B: SmartLock v2 Design Specification (18 Marks)

#### 11. Threat Model Stated (4 Marks)
> "The threat model assumes an active on-path network adversary on the local LAN who can intercept, modify, inject, and replay packets, and knows the protocol spec. However, the attacker cannot access internal device memory, the lock's private RSA key, or ephemeral DH exponents."

#### 12. Per-Stage Mechanisms & Justifications (10 Marks)
> "v2 uses `strong_suites()` to abort on `NULL` (defeating downgrade), RSA certificate validation against a pinned key with Argon2id PIN storage (defeating MITM), ephemeral FFDHE-2048 with bidirectional HKDF (defeating discrete log), deterministic sequence-bound nonces (defeating nonce reuse), and monotonic sequence checking (defeating replay)."

#### 13. v2 Handshake Diagram (4 Marks)
> "My handshake diagram shows explicit transcript hashing and RSA signing during negotiation, followed by HKDF key expansion with `'c2s'` and `'s2c'` context labels, and all subsequent application records protected by AES-GCM with sequence numbers bound as AAD."

---

### Part C: Implementation & Testing (28 Marks)

#### 14. Six Core Defensive Checks in `securelink2.cpp` (18 Marks)
> "`securelink2.cpp` passes all 6 auto-checks: it rejects `NULL` offers, derives directional keys using HKDF (`c2s`/`s2c`), generates deterministic 12-byte nonces (`SL02` || seqno), seals and opens AEAD records with seqno as AAD, throws exceptions on out-of-order/replayed records, and contains zero `md5` or `TODO`."  
> *Run live:* `cd v2_skeleton && ./_scratch_test`

#### 15. v1 Attacks Re-Run, Tamper Rejection & AI Audit (10 Marks)
> "Re-running all v1 attacks against v2 fails: downgrade aborts with an ALERT, MITM aborts on pinned key mismatch, discrete log is computationally infeasible on 2048 bits, and replays throw sequence mismatch errors. In my AI audit, I identified that AI-generated code used random nonces, missed AAD sequence binding, and lacked directional key separation, all of which I corrected."

---

### Part D: Performance Study (8 Marks)

#### 16. Performance Table and Chart (5 Marks)
> "Benchmarking shows v2 handshake latency is 4.94 ms versus 0.60 ms in v1 due to 2048-bit modular exponentiation and RSA signing, with +8 bytes wire framing for sequence numbers. However, steady-state throughput is identical at ~211 MB/s, and per-record seal overhead increases by only 0.26 microseconds."

#### 17. Trade-Off Justification (3 Marks)
> "A 4.34 ms latency increase during connection setup is imperceptible to human users and smaller than typical Wi-Fi jitter. In exchange, it mathematically prevents discrete-log key recovery, stops replay attacks, and prevents unauthorized physical door unlocking, making it the correct engineering trade-off."

---

### Part E: Viva Defense & Live Modifications (10 Marks)

#### 18. Explaining Your Own Exploits & Code (4 Marks)
> "In Task A.3, Baby-Step Giant-Step reduces the search space on the 40-bit prime from $\mathcal{O}(p) \approx 7 \times 10^{11}$ to $\mathcal{O}(\sqrt{p}) \approx 8.4 \times 10^5$, which runs in 0.1s. In Task A.4, identical nonces produce identical AES-CTR keystreams, allowing plaintext recovery via simple XOR cancellation."

#### 19. Live Modification Scenarios (3 Marks)
> - **If asked to repeat a nonce:** "If I hardcode a static nonce in `make_nonce()`, two records will share an identical IV, allowing an attacker to XOR the ciphertexts, cancel the keystream, and leak the plaintext difference."  
> - **If asked about tampering seqno:** "Even if an attacker modifies the sequence prefix on the wire, `seqno` is bound as Additional Authenticated Data (AAD) in AES-GCM, so `EVP_DecryptFinal_ex()` will fail GMAC tag verification and reject the packet."

#### 20. Justifying a Design Choice (3 Marks)
> "I chose RFC 7919 FFDHE-2048 and HKDF because 2048-bit safe primes provide 112 bits of security against discrete log attacks, while HKDF with `'c2s'` and `'s2c'` context labels guarantees uniform key entropy and eliminates reflection attacks."

---

### Report Quality (4 Marks)

#### 21. Report Structure, Evidence & Concision (4 Marks)
> "My report (`23i-0536-G-REPORT.pdf`) strictly follows the required 6-part structure in 13 pages (under the 20-page limit), embedding all 14 empirical screenshot figures and benchmark charts inline alongside the exact Linux commands and mathematical proofs."
