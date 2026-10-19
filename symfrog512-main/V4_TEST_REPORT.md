> **Archived results:** This report describes a previously tested v4 build, not the new v5 writer. See `V5_SIV_DESIGN_AND_TESTS.md` for current tests.

# SymFrog-512 AEAD v4 — targeted mathematics fix and validation report

Date: 2026-10-18 (validation run in supplied environment; reproducible tests included)

## Change applied

**Defect:** In file-format v3 (and historical keyed initialization), the 128-byte key is directly mapped to a 128-byte state and the 32-byte nonce is XORed into the last 32 key bytes. Applying the same arbitrary 32-byte delta to those key bytes and to the nonce left the state identical. This was confirmed at state level and as equal ciphertext and final data tag on equal plaintext/AAD (the separately authenticated header tags were different).

**Correction:** File-format **v4 (`0x00000004`)** performs RFC 5869 HKDF-Extract and HKDF-Expand with HMAC-SHA-512 on the 128-byte raw/Argon2id-derived key (IKM), 32-byte nonce (salt), and a fixed ASCII v4/domain label (info), expanding to exactly 128 bytes of initial state. There is no longer a literal key-tail/nonce XOR in v4. Exact byte-level construction is in `README.md` and `V4_HKDF_REVISION.md`.

**Untouched:** P1024-v3's 24 rounds, χ, constants, other mixing layers and inverses; sponge rate/capacity; ciphertext absorption, tags and AAD; FrogHash-512; Argon2id parameters; file header size and field layout. Encryption writes v4; decryption selects the legacy initialization for v1/v2/v3, so old files remain readable.

## Results verified

| Test | Evidence | Outcome |
|---|---|---|
| Independent HKDF-SHA-512 reference (Python stdlib `hmac`) versus C++ OpenSSL | Exact comparison of all 128 derived state bytes using known fixed key and nonce | PASS |
| Former related-key/nonce identity | 2,048 randomized XOR-related pairs tested with v4; historical v3 equivalence confirmed in regression | PASS — none of 2,048 v4 pairs yielded equal derived states |
| Independent new AEAD KAT | Key `00..7f`, nonce `00..1f`, AAD `0102030405`, 4,097-byte patterned plaintext; file SHA-256 `2f1ea307215670667eda1c23989d089afb5b112fc223aeef3beaa2289a7ba00a` | PASS |
| Legacy v3 KAT fixture | Archived deterministic ciphertext SHA-256 `cd31ad7c2ee7be356b61dff7c831a157b6c8eaa0d5c8f43f1c5a6aa83c01bc36` | PASS: new binary decrypts old fixture |
| Original v2 fixture | SHA-256 `ea3c60d413755e0e19a0edceae878e3c09ba90bdcff78bcff1174e973471b250` | PASS: new binary decrypts old fixture |
| χ and permutation mathematics | 16-entry S-box, maximum DDT 4, max absolute nontrivial LAT 8, 150,000 layer inverse checks and 52,048 full P1024 inverse checks | PASS |
| P1024 one-bit avalanche smoke test | 8,000 trials; mean Hamming distance 512.154/1024 | OBSERVATION, not proof |
| CLI fuzz/robustness battery | 3,049 executions, 215 plaintext lengths, 441 per-byte tamper cases, 1,200 corrupted/malformed inputs, 16 truncations | PASS |
| Safety under wrong keys, wrong AAD, mutated ciphertext | Outputs remain intact on failure | PASS |
| CLI secret-file/input overwrite protections | Raw key/passphrase cannot be overwritten through `--force` | PASS |
| GCC/Clang byte-for-byte regression | Clang O3/O0, GCC O3 and reference build, 12 deterministic encrypt/hash crosschecks | PASS |
| Truncated/fragmented `read()` behavior | 63 (file size, read chunk) combinations | PASS |
| ASan+UBSan builds | 13 CLI size sets and math test under sanitizers | PASS (tested inputs only) |
| Password + Argon2id | MODERATE profile encrypt/decrypt and wrong password rejection | PASS |
| Large streamed file | 33,554,497 bytes (32 MiB + 65), round-trip SHA-256 equal | PASS |
| Nonce sampling | 1,000 independent normal encryptions: 1,000 distinct nonces and ciphertext/tag pairs | PASS (sampling only) |
| FrogHash-512 stability | Old v3 executable and v4 executable produced identical digest on 1 MiB + 67 byte input | PASS |
| Full integrated `--test-all` for v4 | Started; extremely expensive repeated Argon2id trials; exceeded the 140-second test limit | **INCOMPLETE**, not counted as a pass |

## Scope and caveats

This removes the **specific algebraically constructible** related-key/nonce equality. Because the 128-byte key and 32-byte nonce are mapped to a 128-byte initial state, no construction can make this map injective over all possible pairs. HKDF-Extract reduces to a 64-byte SHA-512 PRK; 1,024-bit raw key length does **not** constitute 1,024-bit security. The new initialization has not been proven secure against arbitrary related-key attacks, nonce reuse, or cryptanalysis of the custom permutation/AEAD. These tests do not demonstrate 512-bit confidentiality or authenticity security, and none replace expert cryptanalysis. A protocol-paper update and independent review are needed before considering deployment.

This validation container had the genuine libsodium and OpenSSL **runtime** libraries, but lacked the official `libsodium-dev` headers. Compilation used a temporary libsodium API declarations shim *outside the delivered ZIP*, together with the real runtime libraries. Recompile on Ubuntu with the official headers as described in README; treat the included binary as for local test/reference only. The OpenSSL development headers were present. The historical v1 decryption path is unchanged but was not re-verified with a standalone v1 fixture during this run.

## Local reproduction

```bash
sudo apt update
sudo apt install -y clang lld make pkg-config libsodium-dev libssl-dev python3
make clean && make release
python3 tests/test_v3_compatibility.py
python3 tests/test_v4_init.py
python3 tests/test_v4_kat.py
python3 tests/test_io_regressions.py
python3 tests/test_stress_battery.py
python3 tests/test_large_nonce.py
# Optional, expensive complete checks; can take several minutes:
make check
SYMFROG_BATTERY_QUICK=1 bash tests/run_battery.sh
```

The `tests/fixtures/legacy_v3_rawkey.syf` and `tests/fixtures/v4_hkdf_initial_state.hex` files make decryption compatibility and HKDF state derivation independently reproducible.
