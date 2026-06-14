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
