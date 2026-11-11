#!/usr/bin/env bash
# End-to-end verification tests for NetWatch

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

echo "[1/5] Building NetWatch..."
make clean > /dev/null
make > /dev/null

echo "[2/5] Testing Module 1 & 2 (Connections & Listening Ports)..."
./netwatch --connections > /dev/null
./netwatch --listening > /dev/null

echo "[3/5] Testing Module 3 (/proc Socket-to-PID Mapping)..."
python3 -m http.server 3000 > /dev/null 2>&1 &
TEST_PID=$!
sleep 0.5
MAP_OUT=$(./netwatch --mapping)
kill "$TEST_PID" 2>/dev/null || true
wait "$TEST_PID" 2>/dev/null || true

if ! echo "$MAP_OUT" | grep -q "3000"; then
    echo "FAIL: Module 3 did not detect test server on port 3000"
    exit 1
fi
if ! echo "$MAP_OUT" | grep -q "python3"; then
    echo "FAIL: Module 3 did not map port 3000 to python3"
    exit 1
fi

echo "[4/5] Testing Module 4 & 5 (Real-Time Monitor & Suspicious Port Alert)..."
(sleep 1.2 && python3 -m http.server 4444 > /dev/null 2>&1 & P=$!; sleep 2.5 && kill "$P" 2>/dev/null || true) &
MON_OUT=$(./netwatch -r 2 2)

if ! echo "$MON_OUT" | grep -q "4444"; then
    echo "FAIL: Module 4 did not detect port 4444"
    exit 1
fi
if ! echo "$MON_OUT" | grep -q "ALERT: SUSPICIOUS"; then
    echo "FAIL: Module 5 did not raise suspicious port alert for 4444"
    exit 1
fi

echo "[5/5] Testing Module 6 (Persistent Audit Log)..."
if [ ! -f "logs/netwatch.log" ]; then
    echo "FAIL: logs/netwatch.log was not created"
    exit 1
fi
./netwatch --history 5 > /dev/null

echo "ALL TESTS PASSED."
