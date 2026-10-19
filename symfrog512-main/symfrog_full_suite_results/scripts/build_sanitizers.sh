#!/usr/bin/env bash
set -euo pipefail
clang++ -std=c++23 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer symfrog_full_suite.cpp -o symfrog_full_suite_asan -lsodium -lcrypto
