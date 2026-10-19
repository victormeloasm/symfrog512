> **Update (AEAD v5):** The paper also predates the new v5 synthetic-IV design; neither its original vectors nor its previous security arguments establish v5 security. See `V5_SIV_DESIGN_AND_TESTS.md`. The section below preserves historical v4 errata.

## October 2026 — AEAD v4 construction change

**The paper does not yet describe the new format v4.** Cite this change explicitly rather than treating old vectors/security discussion as current. The full HKDF construction, rationale, vector, and limits are documented in `README.md` (AEAD format v4 section) and `V4_HKDF_REVISION.md`. Only new encryptions use v4. v1/v2/v3 ciphertexts remain readable.

# Paper errata and hardened format v2 notes

This file records differences between arXiv:2602.17900v1 and the hardened implementation in this archive.

## Errata in the v1 paper

### Appendix A.2 `Out(S)` pseudocode

The appendix line

```text
T[i] = S[i] ^ S[i+8]
return SplitMixFinalizer(T)
```

is incomplete and does not match Section 5.4 or the reference implementation. The implemented extraction is:

```text
X_i = S_i
      xor ROTL(S_{8+i}, 17)
      xor ROTL(S_{8+((i+3) mod 8)}, 41)
      xor gamma * (i+1)
Out(S)[i] = SplitMix64Finalizer(X_i)
```

with `gamma = 0x9E3779B97F4A7C15` and little-endian serialization.

### Raw-key CLI length

A 1024-bit raw key is **128 bytes**, represented by **256 hexadecimal characters**. Earlier text mentioning 256 bytes or 2048 hexadecimal characters was incorrect.

### Build flags

The implementation uses C++ exceptions and must not be compiled with `-fno-exceptions`.

### Argon2id stored salt

The legacy implementation stored 32 salt bytes but libsodium's Argon2id API consumed its fixed `crypto_pwhash_SALTBYTES` prefix. Hardened format v2 commits all 32 stored bytes by first deriving the fixed-length Argon2id salt with domain-separated BLAKE2b.

## Hardened format v2 protocol changes

These changes intentionally produce a new transcript and therefore require header version `0x00000002`.

1. Initialization injects the file-format version into the state.
2. The terminal padded ciphertext block, including the pad-only block for exact rate multiples, applies `DS_CT` before permutation.
3. Password-mode KDF profile metadata is stored in the authenticated `reserved` field.
4. Header parsing is strict: unknown flags, malformed metadata, invalid salt use, and length mismatch are rejected.
5. Legacy version `0x00000001` remains decryptable with its historical transcript.

## Security-analysis impact

The ideal-permutation analysis and test vectors in arXiv:2602.17900v1 describe the legacy transcript. A revised paper should:

- define v1 and v2 as separate protocol versions;
- update initialization and terminal ciphertext processing;
- specify the v2 KDF metadata and 32-byte salt commitment;
- publish new v2 known-answer vectors;
- avoid treating empirical avalanche measurements as evidence for resistance to dedicated cryptanalysis;
- explicitly qualify any proof relying on hidden capacity, because the custom output transform combines rate and capacity words.

The last point is not a claim of a practical break. It is a proof-model caveat requiring a dedicated argument or a revised extraction design before making standard sponge-bound claims.

## October 2026: critical P1024-v2 erratum and new P1024-v3

The legacy four-word χ computed all four nonlinear updates **simultaneously**. It is **not bijective**. Setting only the low bits of lanes 0 and 2 to one causes the χ output to equal the all-zero output (an explicit collision). Since subsequent rounds cannot recover lost information, the 24-round P1024-v2 is not a permutation.

The new file format v3 (`0x00000003`) uses sequential updates instead:

```text
x0 ^= (~x1) & x2
x1 ^= (~x2) & x3
x2 ^= (~x3) & x0
x3 ^= (~x0) & x1
```

Each update is an invertible XOR shear. Reversing the order of the four updates inverts the χ layer. The other steps of the round are invertible (XOR constants, XOR mixer, XOR kick operations, rotation and word shuffling), so the full 24-round transformation is bijective.

The legacy χ remains callable only for legacy v1/v2 file decryption. No new ciphertexts are written with it. The v3 KDF and authenticated file metadata follow the hardened v2 convention. The FrogHash-512 initial label changes from `512-V2-` to `512-V3-`, and its new digests are incompatible with the old ones.

**Caution:** Although this closes the mathematical defect, the replacement permutation remains unaudited. All old statistical data and paper analyses apply only to earlier versions. Release of v3 must not be interpreted as a proof or claim of 512-bit real-world security.
