# CS3002 Information Security — Assignment 2
## SmartLock: Break It, Then Build It
**Student Name:** Hassaan Mudassar  
**Roll Number:** 23i-0536  
**Section:** G  
**Institution:** FAST-NUCES  

---

## Build and Environment Reference

- **Operating Environment:** Linux (Ubuntu 22.04 LTS / WSL2)
- **Compiler:** `g++ -std=c++17 -Wall -Wextra -O2`
- **Cryptography Library:** OpenSSL 3.0+ (`libcrypto`, `-lcrypto -lpthread`)

### Primary Build Commands:
```bash
# 1. Build v1 suite
cd smartlock && make

# 2. Build v2 hardened system
cd ../v2_skeleton && make clean && make

# 3. Build and execute Part D performance benchmark
cd ../performance
g++ -std=c++17 -O2 -Wall 23i-0536-G-TASKD-V1.cpp ../v2_skeleton/securelink2.cpp -lcrypto -lpthread -o perf_bench
./perf_bench ../smartlock/instance.txt
```

---

## 1. Scope and Ethics

All investigative procedures, protocol captures, and cryptographic evaluations in this project were conducted exclusively within an isolated private environment. No external networks, real-world hosts, or university infrastructures were accessed or evaluated. All traffic analysis and protocol interactions targeted exclusively the local experimental instance (`smartlock-23i-0536.local`). The analysis was performed strictly for authorized academic evaluation under CS3002 Information Security at FAST-NUCES to identify protocol flaws and engineer the secure SmartLock v2 architecture.

---

## 2. Part A: Protocol Security Analysis (SmartLock v1)

### A.1 Stage 1: Negotiation — Cipher Suite Downgrade
- **Protocol Weakness:** The client's cipher offer in `type:HELLO` is transmitted as cleartext without message authentication. The server's negotiation policy allows the insecure `NULL` suite, and neither side authenticates the negotiation transcript.
- **Vulnerability Mechanics:** An on-path network attacker intercepts the `HELLO` message and modifies the parameter list from `suites:AES256-GCM,AES128-GCM,NULL` to `suites:NULL`. The server selects `NULL`, disabling record encryption entirely.
- **Security Property Broken:** **Confidentiality and Integrity.**

### A.2 Stage 2: Authentication — Certificate Pinning Failure & Digest Reversal
- **Protocol Weakness:** The client accepts the server's certificate without validating it against a pinned public key or a Certificate Authority (CA). Additionally, the device authentication secret (PIN) is transmitted as an unsalted MD5 digest in the `PAIR` message.
- **Vulnerability Mechanics:** 
  1. An attacker presenting an arbitrary self-signed certificate can impersonate the device.
  2. Because the pairing PIN format consists of a dictionary word followed by three digits (approx. $2 \times 10^7$ search space), matching the captured digest `d823a25d5a3ef11f9e1c69a690872def` against `smartlock/pin_wordlist.txt` recovers the original PIN in under one second:
     $$\mathbf{PIN = \texttt{sunset625}}$$
- **Security Property Broken:** **Authentication and Credential Secrecy.**

### A.3 Stage 3: Keying — Small-Group Discrete Logarithm & Key Derivation
- **Protocol Weakness:** The Diffie-Hellman key exchange utilizes a small 40-bit prime modulus ($p = 705001380739$), a static private exponent $b$, and zero-pads the raw integer secret directly into an AES key without a Key Derivation Function (KDF).
- **Vulnerability Mechanics:** Given $p$, generator $g = 2$, and public value $B = 381871777500$, the discrete logarithm $B \equiv g^b \pmod p$ is solved using the Baby-Step Giant-Step algorithm in $O(\sqrt{p})$ operations:
  $$\mathbf{dh\_b = 263367402911}$$
  Combining $b$ with the client's public value $A$ computes the shared secret $s = A^b \pmod p$, revealing the session key and decrypting the pairing secret:
  $$\mathbf{Flag = \texttt{FLAG\{9c9b2d45321061f6\}}}$$
- **Security Property Broken:** **Forward Secrecy and Key Confidentiality.**

### A.4 Stage 4: Message Protection — Keystream Reuse in GCM Mode
- **Protocol Weakness:** The implementation reuses a single static initialization vector (`static_nonce = 1deb1b5c316e24acd9176cde`) across all AES-GCM records.
- **Vulnerability Mechanics:** In Counter mode, identical nonces produce identical keystreams ($KS$). XORing two ciphertexts cancels the keystream:
  $$C_1 \oplus C_2 = (P_1 \oplus KS) \oplus (P_2 \oplus KS) = P_1 \oplus P_2$$
  Knowing the structure of the status reply $P_2 = \texttt{"STATE LOCKED unlocks=0"}$, an observer recovers $P_1$:
  $$\mathbf{nonce\_xor\_hex = \texttt{0335282620446c382a3f2d6473180f1e1b2f0410561e}}$$
- **Security Property Broken:** **Confidentiality and Authenticity.**

### A.5 Stage 5: Teardown & Ordering — Replay Attack
- **Protocol Weakness:** Records lack sequence numbers, freshness tokens, or timestamps. Furthermore, teardown is performed via an unauthenticated raw socket disconnect.
- **Vulnerability Mechanics:** An eavesdropper who captures a valid encrypted `UNLOCK` record can retransmit the exact wire payload in a future connection. The server decrypts the record under the repeated key/nonce and increments the unlock counter without detecting staleness.
- **Security Property Broken:** **Message Freshness, Integrity, and Physical Access Control.**

---

## 3. Part B: SmartLock v2 Design Specification

### 3.1 Threat Model
- **Attacker Capabilities:** An active on-path adversary on the local network who can read, modify, inject, delay, reorder, and drop messages in transit, with full knowledge of the protocol specification.
- **Attacker Limitations:** The attacker does not possess the lock's long-term RSA private key (`rsa_priv_b64`), the ephemeral Diffie-Hellman private exponents ($a, b$), or the derived directional session keys ($K_{c2s}, K_{s2c}$).
- **v2 Security Goals:** Mutual authentication, payload confidentiality and integrity, resistance to replay and reordering attacks, and forward secrecy.

### 3.2 Per-Stage Security Mechanisms

| Stage | SmartLock v2 Mechanism | Mitigated Vulnerability |
| :--- | :--- | :--- |
| **Negotiation** | `strong_suites()` accepts only `AES256-GCM` and `AES128-GCM`. `choose_suite()` returns `""` (abort) on weak or unknown offers. Server signs negotiation transcript. | Prevents downgrade to `NULL`. |
| **Authentication** | Lock signs its identity certificate with RSA; Hub pins `rsa_pub_b64`. PIN security design: at rest, hashed using salted Argon2id/scrypt; on wire, transported only within the authenticated channel. | Prevents rogue device impersonation and dictionary attacks. |
| **Keying** | Ephemeral RFC 3526 2048-bit MODP Diffie-Hellman with signed transcript (`offer\|suite\|B`). Keys derived via HKDF-SHA256 (`sl2::derive_key`) with directional contexts (`c2s`, `s2c`). | Renders discrete log intractable and guarantees forward secrecy and key separation. |
| **Message Protection** | AES-256-GCM AEAD. `sl2::make_nonce(seqno)` generates unique 12-byte nonces. 8-byte sequence counter bound as Additional Authenticated Data (AAD). | Eliminates keystream reuse and prevents ciphertext manipulation. |
| **Teardown** | Monotonic sequence counters enforced in `open_record()`. Close command (`QUIT`) is authenticated within the sequence. | Eliminates command replay and truncation attacks. |

---

## 4. Part C: Implementation & Verification

### 4.1 Verification Matrix: v1 vs v2

| Evaluation Vector | SmartLock v1 Result | SmartLock v2 Result | Property Restored |
| :--- | :--- | :--- | :--- |
| **Cipher Downgrade** | Accepted `NULL`; plaintext exposed. | Negotiation aborted; session closed. | Confidentiality |
| **MITM / Impersonation** | Accepted unverified certificates. | Aborted on pinned key mismatch. | Authentication |
| **Key Recovery** | 40-bit DH solved in $<1$ second. | 2048-bit DH discrete log intractable. | Forward Secrecy |
| **Nonce Reuse** | Keystream canceled via $C_1 \oplus C_2$. | Unique nonce per record. | Confidentiality |
| **Command Replay** | Replayed `UNLOCK` incremented counter. | Rejected with sequence mismatch error. | Freshness & Integrity |

### 4.2 Cryptographic Audit Findings
1. **OpenSSL 3 EVP Agility:** Used `EVP_KDF_fetch` and `OSSL_PARAM` rather than deprecated functions, ensuring forward-compatible cryptographic agility.
2. **Directional Separation:** Separate HKDF contexts (`c2s` vs `s2c`) eliminate cross-direction reflection vulnerabilities.
3. **Sequence Number Binding as AAD:** Feeding the 8-byte big-endian sequence counter into the GCM AAD ensures any tampering with the sequence header causes tag verification failure before decryption.

---

## 5. Part D: Performance Study

### 5.1 Measurement Results

All tests executed with `g++ -O2` on the experimental platform:

| Metric | v1 (Baseline) | v2 (Hardened) | Difference |
| :--- | :--- | :--- | :--- |
| **Handshake Latency (mean)** | 0.60 ms | 4.94 ms | +4.34 ms (8.27×) |
| **Handshake StdDev ($\sigma$)** | 0.69 ms | 1.18 ms | — |
| **Wire Overhead per Record** | +16 bytes (tag) | +24 bytes (seqno + tag) | +8 bytes |
| **Record Seal Time (mean)** | 1.87 $\mu$s | 2.03 $\mu$s | +0.17 $\mu$s |
| **Record Open Time (mean)** | 1.79 $\mu$s | 2.05 $\mu$s | +0.25 $\mu$s |
| **1 KiB Throughput (mean)** | 208.2 MB/s | 211.5 MB/s | ~101.6% (Hardware AES-NI) |
| **Throughput StdDev ($\sigma$)** | 15.1 MB/s | 14.4 MB/s | — |

*Visual distribution chart referenced: `performance/benchmark_chart.png`.*

### 5.2 Performance Trade-Off Justification
The hardened protocol introduces a modest 4.3 ms latency increase during session establishment, attributable to 2048-bit modular exponentiation and RSA-2048 signing/verification. In steady-state operation, the per-record processing time difference is less than 0.25 microseconds, maintaining throughput above 200 MB/s. For an embedded physical door lock, a 4.3 ms handshake cost is imperceptible to users and negligible compared to standard network jitter, while providing mathematical protection against unauthorized entry, replay attacks, and key recovery.

---

## 6. Summary of Parameters (answers.txt)

```text
roll           = 23i-0536
flag           = FLAG{9c9b2d45321061f6}
recovered_dh_b = 263367402911
cracked_pin    = sunset625
nonce_xor_hex  = 0335282620446c382a3f2d6473180f1e1b2f0410561e
```

