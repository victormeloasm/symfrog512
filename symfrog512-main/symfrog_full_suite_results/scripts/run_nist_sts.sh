#!/usr/bin/env bash
set -euo pipefail
BYTES="${1:-12500000}"
OUT="nist_input.bin"
./symfrog_full_suite --emit-hash-stream "$BYTES" > "$OUT"
echo "Feed $OUT into the NIST STS harness."
