#!/usr/bin/env bash
set -euo pipefail
BYTES="${1:-104857600}"
./symfrog_full_suite --emit-hash-stream "$BYTES" | dieharder -a -g 200
