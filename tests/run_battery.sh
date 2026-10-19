#!/usr/bin/env bash
# Build and run the extended tests on a Linux machine with libsodium-dev and libssl-dev.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p battery_test_results
make release
make check
python3 tests/test_stress_battery.py
clang++ -std=c++23 -O2 -fno-rtti tests/test_math_battery.cpp -o math_battery -lsodium -lcrypto
./math_battery | tee battery_test_results/math_battery.log
clang++ -std=c++23 -O1 -g -fno-omit-frame-pointer -fno-rtti \
  -fsanitize=address,undefined -fno-sanitize-recover=all \
  tests/test_math_battery.cpp -o math_battery_san -lsodium -lcrypto
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 ./math_battery_san | tee battery_test_results/math_battery_sanitized.log
clang++ -std=c++23 -O3 -fno-rtti src/symfrog512.cpp -o build_clang_o3 -lsodium -lcrypto
clang++ -std=c++23 -O0 -fno-rtti src/symfrog512.cpp -o build_clang_o0 -lsodium -lcrypto
g++ -std=c++23 -O3 -fno-rtti src/symfrog512.cpp -o build_gcc_o3 -lsodium -lcrypto
clang++ -std=c++23 -O1 -g -fno-omit-frame-pointer -fno-rtti \
  -fsanitize=address,undefined -fno-sanitize-recover=all \
  src/symfrog512.cpp -o build_clang_san -lsodium -lcrypto
cc -O2 -shared -fPIC tests/read_fragmentation.c -o read_fragmentation.so -ldl
python3 tests/test_crossbuild_and_fragment.py
python3 tests/test_large_nonce.py
printf 'ALL EXTENDED TESTS PASSED\n'
