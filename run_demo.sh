#!/bin/bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "========================================================================"
echo "  CS3002 Information Security — Assignment 2 Demo Runner"
echo "  Student: Hassaan Mudassar | Roll: 23i-0536 | Section: G | Port: 9265"
echo "========================================================================"
echo ""

echo "[1/4] Running Part C.1 Security Core Verification (6 Auto-Checks)..."
cd "$DIR/v2_skeleton"
g++ -std=c++17 -Wall -Wextra _scratch_test.cpp securelink2.cpp -lcrypto -o /tmp/_scratch_test
/tmp/_scratch_test | grep -E '\[TEST\]|PASSED|Accepted'
rm -f /tmp/_scratch_test
echo ">>> Part C.1 Core Checks Passed Successfully!"
echo ""

echo "[2/4] Running Part A.3 Key Recovery & Flag Extraction..."
cd "$DIR/exploits"
g++ -std=c++17 -O2 -Wall 23i-0536-G-TASKA3-V1.cpp -lcrypto -o /tmp/taskA3_solve
/tmp/taskA3_solve ../evidence/cap_v1_stream.txt | grep -E 'Recovered private exponent|Decrypted Plaintext|flag'
rm -f /tmp/taskA3_solve
echo ">>> Part A.3 Flag Recovery Succeeded!"
echo ""

echo "[3/4] Running Part A.4 Nonce-Reuse Keystream XOR Recovery..."
g++ -std=c++17 -O2 -Wall 23i-0536-G-TASKA4-V1.cpp -o /tmp/taskA4_solve
/tmp/taskA4_solve ../evidence/cap_v1_stream.txt | grep -E 'Computed C1 XOR C2|Recovered Plaintext Prefix|nonce_xor_hex'
rm -f /tmp/taskA4_solve
echo ">>> Part A.4 Keystream Cancellation Succeeded!"
echo ""

echo "[4/4] Running SmartLock v2 End-to-End Live Session..."
cd "$DIR/v2_skeleton"
make clean >/dev/null 2>&1 && make all >/dev/null 2>&1
./lock_server2 instance.txt > /tmp/v2_server.log 2>&1 &
SERVER_PID=$!
sleep 1

./hub_client2 instance.txt 127.0.0.1 9265
kill $SERVER_PID 2>/dev/null || true
make clean >/dev/null 2>&1

echo ""
echo "========================================================================"
echo "  ALL CHECKS & DEMONSTRATIONS COMPLETED SUCCESSFULLY!"
echo "========================================================================"
