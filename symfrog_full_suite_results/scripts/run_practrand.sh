#!/usr/bin/env bash
set -euo pipefail
BYTES="${1:-1073741824}"
./symfrog_full_suite --emit-hash-stream "$BYTES" | RNG_test stdin64
