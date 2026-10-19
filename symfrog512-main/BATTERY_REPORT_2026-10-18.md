# SymFrog-512 P1024-v3 — extended test battery

**Scope:** functional correctness, memory safety, mathematical invariants, file-format compatibility, negative testing, I/O robustness, and exploratory statistical checks. **Not** a security proof or an independent cryptanalytic certification.

**Source under test:** original audited `src/symfrog512.cpp` SHA-256 `d2fefb7f3c5cd20afd737a2a180581a1fecd489dc5a3a6aeacb0cde4284741d0`, followed by the minimal secret-file overwrite safety fix, yielding SHA-256 `83e1d0f5f963b0ec27df1de828f0a93f9bf41b547108c1ed2116f576d4000768`.

## Result: functional checks PASS; one I/O bug fixed; one structural design limitation confirmed

| Area | Result | Details |
|---|---|---|
| Integrated built-in tests | **PASS** | Full `--test-all` completed on the audited build (before the CLI-only secret-file fix): chi/round inverses, built-in AEAD and KDF tests, tampering and boundaries |
| Randomized AEAD round-trips | **PASS** | 215 distinct sizes, from 0 to 1,048,577 bytes, including block boundaries and patterned/random plaintext |
| Extended CLI robustness | **PASS** | 3,049 subprocess executions on patched build |
| Exhaustive byte tampering | **PASS** | Each of 441 bytes of a 257-byte ciphertext container independently flipped; all rejected without replacing the existing output |
| Mutational/format fuzz tests | **PASS** | 1,200 corrupted or malformed inputs rejected; 16 truncations rejected |
| Nonce handling | **PASS** | Deterministic explicit nonces reproduce vectors; zero explicit nonce rejected; 1,000 random encryptions produced 1,000 distinct 256-bit nonces and ciphertext/tag sequences |
| Raw key/AAD controls | **PASS** | Wrong key and AAD rejected, malformed keys rejected, symlink and input overwrite checks passed |
| Key/passphrase source overwrite | **FIXED / PASS** | Previously, `enc plaintext keyfile --key-file keyfile --force` replaced the **key itself** with ciphertext. A CLI guard now forbids using the key/passphrase file (or same-inode hardlink) as `enc`/`dec` output. 6 added regressions cover this |
| Full P1024-v3 inversion | **PASS** | 52,048 round-trip inversions (50,000 randomized + 1,024 basis + 1,024 complemented basis states) |
| Layer inversions | **PASS** | 150,000 independent checks (chi, kick, rotate/shuffle) |
| χ small S-box | **PASS** | All 16 4-bit inputs have distinct outputs; maximum DDT entry for nonzero input delta = 4; maximum absolute nontrivial LAT = 8 |
| P1024 one-bit avalanche | **OBSERVED** | 8,000 differential trials, mean output HD = 512.154/1024; SD = 15.826; min = 460, max = 577; largest individual output-bit flip-frequency deviation from 0.5 = 0.018875 |
| FrogHash-512 avalanche | **OBSERVED** | 256 one-bit-input differential pairs, mean HD = 256.969/512; SD = 11.289; no collision observed in the 512 generated digests |
| Compiler crosschecks | **PASS** | Clang O0/O3 and GCC O3 produced byte-identical ciphertext (with fixed nonce/key) and digests on 58 sizes before the CLI fix; 12 sizes after the CLI fix |
| Short `read()` returns | **PASS** | LD_PRELOAD fragmentation at 1/7/31/63/64/65/127 bytes: 196 (size,chunk) combinations before, 63 combinations after the fix; encrypt/decrypt/hash output matched unfragmented reference |
| Sanitizers | **PASS** | AddressSanitizer + UndefinedBehaviorSanitizer: 13 input sizes per run for enc/dec/hash and mathematical battery including 150k layer inversions and 52k permutation inversions; no sanitizer diagnosis |
| v2 compatibility, v3 KAT | **PASS** | Original v2 fixture decrypted; deterministic v3 SHA-256 KAT `cd31ad7c2ee7be356b61dff7c831a157b6c8eaa0d5c8f43f1c5a6aa83c01bc36` unchanged |
| Large file | **PASS** | Encrypt/decrypt round-trip for 33,554,497 bytes (32 MiB + 65), SHA-256 comparison equal |
| Password mode | **PASS** | MODERATE Argon2id pass-file encryption/decryption, KDF2 header metadata, wrong-password rejection without clobbering an existing output |

### Important mathematical/design observation: related-key / nonce equivalence

The initial keyed state directly loads 128 bytes (1024 bits) of raw key. The final 32 key bytes are XORed with the 32-byte nonce before applying P1024-v3. Thus, with all other key bytes fixed, for any nonzero 32-byte delta `Δ`:

```
key_prime[96:128] = key[96:128] XOR Δ
nonce_prime       = nonce       XOR Δ

state(key_prime, nonce_prime) = state(key, nonce)
```

This identity was verified both on the internal initial state and through independently generated encryptions: under two distinct but related `(key, nonce)` pairs, the ciphertext and **final data tag** were identical for the same plaintext and AAD. The file headers and separately authenticated **header tags** differ because they contain their respective nonces. This is **not** an observed practical forgery under a single unknown key; it **is** a proven related-key equivalence in the current initialization function. It limits claims of cross-key uniqueness and must be assessed explicitly in a threat model or peer review.

**No protocol or cryptographic change was made to remove this equivalence**, because doing so would change published behavior, KATs and the paper's mathematical specification. A future protocol revision, if authorized, would require its own version number and updated article/test vectors. A more rigorous independent design analysis is still required.

### Actual defect fixed: accidental destruction of secret source file

A successful reproduction against the earlier audited binary showed `enc input key --key-file key --force` returning exit code 0 while replacing the original 128-byte key file with a 200-byte ciphertext container. The patch adds one guard before the `enc`/`dec` file API. It rejects an output path resolving to the same existing regular-file inode as the `--key-file` or `--pass-file` input, including same-inode hardlinks. The existing no-clobber/atomic-write semantics for other output files remain unchanged.

**Unchanged:** χ, P1024-v3, all round constants, output transform, domain separation, KDF parameters, tags, header layout, format version, nonce generation, and the public KAT. Source diffs consist only of the new guard and its two CLI call sites; test code is separate.

### Limitations and environment

- No formal proof of AEAD security, nonce-misuse resistance, random-oracle behavior, or arbitrary related-key security. Nonce reuse is already known to expose plaintext XOR relationships.
- The mathematical inversion routine is a round-trip implementation test, not an independent mathematical proof. The explicit sequential XOR-shear structure supplies the bijectivity argument.
- Small-sample avalanche, bit balance and smoke collision tests cannot establish collision resistance or preimage resistance of a 512-bit hash, nor rule out sophisticated differential/linear distinguishers.
- Sanitizer coverage is not exhaustive and does not substitute for third-party code review or coverage-guided fuzzing over extended time scales.
- This container had the genuine libsodium/OpenSSL **runtime libraries** but not `libsodium-dev` headers. Compilation used a temporary declarations shim, **not** included in the delivered ZIP. Please rebuild against the official `libsodium-dev` and `libssl-dev` headers on your Ubuntu system.
- The full built-in `--test-all` completed **before** the CLI-only key-file overwrite patch. After the patch: new I/O regressions, v2/v3 KAT, 3,049-case stress battery, cross-compiler quick battery, large-file/nonce smoke, and ASan/UBSan mathematical battery all passed. The longer original cross-build fragmentation sweep also passed before patch; a repeat with overly heavy one-byte fragmentation hit the execution budget, so the post-patch sweep used fewer (size,chunk) combinations.

### New reproducible test files

- `Makefile` also explicitly selects the documented LLVM `lld` linker, fixing a reproduced Clang LTO build failure (`LLVMgold.so` absent in the validation environment). This is a build-only change.
- `tests/test_math_battery.cpp`
- `tests/test_stress_battery.py`
- `tests/test_crossbuild_and_fragment.py`
- `tests/test_large_nonce.py`
- `tests/read_fragmentation.c`
- `tests/run_battery.sh`
- `battery_test_results/*.json` and `battery_test_results/*.log`

The supplied `run_battery.sh` is intended for Linux with Clang, GCC, the official libsodium/OpenSSL development headers, and Python 3. The full run has intentionally expensive KDF/short-read cases; `SYMFROG_BATTERY_QUICK=1 bash tests/run_battery.sh` selects a shorter cross-compiler/fragmentation subtest. Results are reproducible at the *property/test* level; entropy-derived nonce values and timings will naturally differ.
