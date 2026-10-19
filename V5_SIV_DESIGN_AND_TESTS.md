# SymFrog-512 AEAD v5 — Experimental synthetic IV revision

**Date:** 2026-10-18 (implementation/test follow-up). **Status:** experimental research, not an audited or standardized misuse-resistant AEAD.

## Scope of the correction

The previous v4 writer generated the same keystream on a repeated nonce under the same key and AAD. A direct chosen-plaintext regression demonstrated `C1 XOR C2 = P1 XOR P2` for 64 bytes. Version 5 replaces its *writer's nonce construction* with a synthetic IV (SIV-style two-pass encryption) derived by an independently keyed, standard HMAC-SHA-512 calculation. The actual SymFrog P1024-v3 permutation, χ, 24 rounds, final tag extraction and FrogHash-512 remain unchanged. The state HKDF uses a new versioned `info` label; the file version is incremented to 5.

This is an **experimental composition**: HKDF/HMAC are standard primitives, but the underlying custom duplex cipher has no general proof of IND-CPA security or integrity bounds. A complete misuse-resistance theorem has **not** been established. To claim a standardized misuse-resistant AEAD, use a vetted implementation of AES-SIV (RFC 5297) or AES-GCM-SIV (RFC 8452), not this custom cipher.

## Exact serialization and domain separation

Keep the **152-byte** header `SYMFROG1 | LE32(version=5) | LE32(flags) | salt[32] | nonce[32] | LE64(ct_len) | reserved[32] | header_tag[32]` and append ciphertext and `final_tag[32]`. In v5, `salt` is the public nonce (also password KDF salt), and `nonce` is the derived synthetic IV. Raw-key v5 headers must have a nonzero public `salt` (the old versions require zero). V2/V3/V4 decryption paths, field validation and known-answer fixtures remain intact.

Given the current raw or Argon2id-derived 128-byte key `K`, associated data `A`, plaintext `P`, header `H`, and the header's public salt `U`:

1. `MACKEY = HKDF-SHA512(IKM=K, salt=U, info="SymFrog-512 AEAD v5 | synthetic IV MAC key | HKDF-SHA-512", L=64)`.
2. `H0 = serialize(H with nonce[32]=0 and header_tag[32]=0)`.
3. `SIV = first_32_bytes(HMAC-SHA512(MACKEY, ASCII("SymFrog-512 AEAD v5 | SIV transcript | header, AAD, plaintext") || H0 || LE64(len(A)) || A || P))`.
4. Write `H.nonce=SIV`. Compute the SymFrog keyed initial state with HKDF-SHA512, `IKM=K`, `salt=SIV`, `info="SymFrog-512 AEAD v5 | P1024-v3 | synthetic IV | HKDF-SHA-512"`, `L=128`; map little-endian and invoke the unchanged P1024-v3 encryption transcript.
5. The old v4 header tag and final ciphertext authentication mechanisms are retained with the versioned v5 HKDF initialization; decryption first authenticates the ciphertext, then decrypts to a 0600 temp file and recomputes/compares the SIV before committing output.

Password-derived files use `salt` for Argon2id as they did in v4; public-nonce overrides also change this salt. Default operation generates a new uniformly random 256-bit `salt` and a content-derived IV. The same `K, U, A, P, flags, KDF metadata` yields the same ciphertext, leaking equality; different `P` or `A` changes SIV under normal PRF assumptions. HMAC-SHA512 is not a proof of global AEAD security.

## Test results in the supplied environment

| Validation | Observed result |
| --- | --- |
| Independent Python HKDF/HMAC reconstruction of C++ SIV | PASS for all tested sizes |
| Deterministic v5 KAT | SHA-256 `95e6713726497ae89e24bb6be5ce3282174bed91d0bfe2f1b3c6d3db806fcbca` |
| KAT key/nonce/AAD | Raw key = bytes 0…127; public nonce = `12` repeated 32 bytes; AAD = `01020304` |
| KAT plaintext | 4097 bytes, `P[i] = (i*29+4097) mod 256` |
| Same public nonce/key, different plaintext | Different SIV; 64-byte XOR-keystream reuse identity not observed |
| Same key, nonce, AAD, plaintext | Deterministic identical ciphertext, as designed |
| AAD modified, ciphertext/tag/header modified, incorrect key | Rejected without overwriting existing output |
| v5 file sizes | 0,1,7,31,63,64,65,127,128,129,4097,1,048,641 bytes; PASS |
| Previous v4 known-answer ciphertext | Decrypted and compared with frozen plaintext: PASS |
| Legacy v2/v3 fixtures | PASS |
| Full built-in `--test-all` (includes password mode / Argon2id) | `ALL TESTS PASSED` |
| Extended black-box robustness | 3,049 processes; 215 round-trips; 441 single-byte corruptions; 1,200 mutated ciphertexts; PASS |
| Mathematical layer inverse and permutation invertibility | 150,000 + 52,048 checks; PASS |
| Avalanche | 8,000 one-bit tests; mean HD 512.154125 / 1,024; statistical test only |
| 32 MiB + 65 byte roundtrip, 1,000 fresh public nonces | PASS, no repeat in sampled random nonces |
| Clang -O1 / -O3, GCC -O3, Clang with ASan+UBSan | Matched bytes for 6 test message sizes; sanitized v5 regression PASS |

**Build limitation:** The execution environment included the libsodium runtime but not the official libsodium development headers. For local tests a temporary C-compatible declaration shim was used against the installed runtime (`libsodium.so.23`). That shim is *not part of the source archive*. Rebuild on the intended Ubuntu system with `libsodium-dev`, `libssl-dev`, `clang`, `lld` and run the included test commands using official headers before publishing binaries.

## What remains unproven

- Multi-round differential, linear, integral, SAT/SMT distinguishers of P1024-v3.
- A meaningful forgery bound for the complete duplex AEAD, including its 256-bit tag and output transform.
- A reduction proving nonce-misuse resistance for this custom SIV-style composition. Neither an HMAC regression nor a repeated-nonce test constitutes such a proof.
- Side-channel behavior under realistic microarchitectural and compiler conditions. Sanitizers do not validate constant-time execution.
- Full independent legacy v1-format test vector: the decoder remains, but no original fixture was available in this battery.

The reversible SplitMix64 finalizer in `output_transform_rate` is not inherently an exploitable state-recovery flaw. It cannot be promoted to a cryptographic one-way function; instead, the complete output construction requires cryptanalysis. No arbitrary modification to P1024-v3 or the output mixer was made without a reproducible attack.

## Reproduction on Ubuntu (with development packages)

```bash
sudo apt install clang lld g++ make libsodium-dev libssl-dev python3
make release
python3 tests/test_v5_siv.py
python3 tests/test_v3_compatibility.py
python3 tests/test_v4_init.py
python3 tests/test_io_regressions.py
./symfrog512 --test-all
bash tests/run_battery.sh
```

The comprehensive battery repeats memory-hard Argon2id operations, so it can take substantially longer than the focused regression. Read historical v4 tests as archived writer tests, not v5 writer KATs.
