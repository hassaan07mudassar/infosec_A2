========================================================================
SmartLock v2: Break It, Then Build It — CS3002 Information Security
Hassaan Mudassar — 23i-0536 — Section G
========================================================================

1. ENVIRONMENT & REQUIREMENTS
-----------------------------
- OS: Linux (Ubuntu 22.04 LTS / Debian / Kali Linux / WSL2)
- Compiler: g++ (version 11 or newer, C++17 support)
- Libraries: OpenSSL 3.0+ libcrypto (sudo apt install build-essential libssl-dev)

2. COMPONENT BUILD INSTRUCTIONS
-------------------------------
A. Build v1 Tools and Generate Instance:
   $ cd smartlock
   $ make
   $ ./instance_generator 23i-0536
   (Writes instance.txt for roll 23i-0536; lock listens on port 9265)

B. Build v2 Hardened System:
   $ cd ../v2_skeleton
   $ make clean && make
   (Compiles lock_server2 and hub_client2 linking against securelink2.cpp)

C. Build and Run Part D Performance Benchmark:
   $ cd ../performance
   $ g++ -std=c++17 -O2 -Wall 23i-0536-G-TASKD-V1.cpp ../v2_skeleton/securelink2.cpp -lcrypto -lpthread -o perf_bench
   $ ./perf_bench ../smartlock/instance.txt

3. RUNNING SMARTLOCK V2 (END-TO-END)
------------------------------------
Ensure instance.txt is present in v2_skeleton:
   $ cp ../smartlock/instance.txt ../v2_skeleton/

Terminal 1 (Lock Server):
   $ cd v2_skeleton
   $ ./lock_server2 instance.txt

Terminal 2 (Hub Client):
   $ cd v2_skeleton
   $ ./hub_client2 instance.txt 127.0.0.1 9265

Expected Output:
- Hub negotiates AES256-GCM (refusing NULL)
- Hub authenticates lock certificate against pinned rsa_pub_b64
- Ephemeral 2048-bit DH exchange with RSA-signed transcript
- Bidirectional HKDF key derivation (c2s and s2c)
- Sequence-bound AEAD record loop executes: STATUS, UNLOCK, LOCK, QUIT

4. RUNNING TEST SUITE (AUTO-CHECKS 1-5)
---------------------------------------
   $ cd v2_skeleton
   $ g++ -std=c++17 -Wall -Wextra _scratch_test.cpp securelink2.cpp -lcrypto -o _scratch_test
   $ ./_scratch_test

All assertions pass:
- Check 1: Strong suites and downgrade rejection
- Check 2: HKDF-SHA256 key derivation with direction separation
- Check 3: Unique 12-byte nonce per sequence number
- Check 4: AEAD seal/open round-trip
- Check 5: Replay and tampered record rejection
- Check 6: Source scan clean (zero md5/TODO, contains hkdf/evp_kdf)
========================================================================

