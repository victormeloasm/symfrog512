# Changelog

## AEAD format v5 experimental SIV-style update (October 2026)

- Separate the public nonce (`salt[32]`) from the synthetic IV (`nonce[32]`) with the same 152-byte authenticated file header.
- Derive a 64-byte independent SIV MAC key via HKDF-SHA-512 and compute the 32-byte synthetic IV as HMAC-SHA-512 over the canonical header, AAD length, AAD and complete plaintext.
- Use domain-separated v5 HKDF initial-state derivation, preserving P1024-v3, χ, 24 rounds, absorption, final-tag extraction and FrogHash.
- Decrypt v1–v4 with historical semantics; add a frozen v4 ciphertext fixture and independent Python HMAC/KDF verification.
- Require a public salt for v5 raw-key files; reject invalid v5 headers; enforce SIV recomputation before committing plaintext to disk.
- Preserve the original v4 HKDF known-answer test as historical, not as a new writer output.
- Note open differential, linear, state-recovery, security-bound, side-channel and misuse-resistance questions; no independent security proof is claimed.

# AEAD v4 HKDF-SHA-512 revision (2026-10-18)

- Replaced the v4 *initial keyed state only* with RFC 5869 HKDF-SHA-512 (nonce as salt, raw/Argon2id key as IKM, explicit v4 ASCII info string). Eliminates the demonstrated XOR-related key/nonce initial-state identity.
- Updated new file format to `0x00000004`, preserving authenticated 152-byte header and final tag format.
- Preserved exact decryption for v1/v2/v3. The v3 known-answer ciphertext was saved as a reference fixture.
- P1024-v3, χ, 24 rounds, FrogHash, Argon2id costs, AEAD ciphertext absorption and final tag calculation are unchanged.
- Added an independent Python HMAC/HKDF reference, a deterministic v4 KAT, and regression tests for key/nonce pair equivalence and integrity.
- Known limits: this is a targeted design improvement, not a cryptographic security certification; related-key security and nonce reuse resistance are not proven.

## P1024-v3 / file format v3 (October 2026)

### Critical mathematical correction

- Identified a collision in the v1/v2 four-lane parallel χ layer (`0000` and `1010`, where lane order is `[x0,x1,x2,x3]`). Therefore the old 24-round core was **not a permutation**.
- Replaced the v3 χ with sequential nonlinear XOR shears, with an explicit inverse implemented and exercised in `--test-all`. This establishes **bijectivity only**, not security against cryptanalysis.
- Added version-selected legacy χ for v1/v2 **decryption only**, preventing silent breakage of historic ciphertexts.
- New encryption writes header version 3; KDF salt commitment, header authentication, strict validation and ciphertext-domain padding remain as in v2.
- The `hash` command now uses P1024-v3 and a v3 domain label; old hashes are intentionally **not compatible**.
- Added bijectivity regression tests, with 4-bit exhaustive χ cases and full-state inverse tests.
- Updated the structural inspector for v3 and marked historical test data as not providing any v3 evidence.
- The 2026-02 arXiv paper describes an older construction and requires an updated analysis.

### Migration

Use the updated program to decrypt old v1/v2 `.syf` files with their original key/passphrase and re-encrypt to new v3 files using **fresh random nonces**. Confirm plaintexts, back up data, and only then remove old files. Existing v1/v2 ciphertexts remain decryptable, but old versions of the application do not support v3.

## Hardened format v2

### Cryptographic transcript

- New files use header version `0x00000002`.
- The format version is injected into initialization for protocol separation.
- The terminal padded ciphertext block now receives `DS_CT` before permutation.
- Password mode commits all 32 stored salt bytes into the effective Argon2id salt using a domain-separated BLAKE2b compression to libsodium's required salt length.
- The Argon2id profile is encoded in authenticated header metadata.
- Legacy v1 decryption preserves the historical transcript and KDF behavior.

### Decryption safety

- Full ciphertext authentication occurs before a plaintext output file is created.
- A second verification is performed during decryption to detect concurrent ciphertext mutation.
- Header length mismatches and malformed metadata are rejected rather than tolerated.

### File-system hardening

- Inputs are opened with `O_NOFOLLOW` and must be regular files.
- Input/output inode equality is rejected.
- Encryption detects source-file size, mtime, or ctime changes during the operation.
- Temporary outputs are forced to mode `0600`.
- Existing output paths are protected by an atomic no-replace commit unless `--force` is supplied.
- Output and parent-directory synchronization are retained.

### Secret handling

- Added `--pass-prompt`, `--pass-file`, and `--key-file`.
- Legacy argv secret options emit warnings and are wiped from the process argument buffer after parsing when possible.
- Empty passphrases are rejected.
- Tag comparison now uses `sodium_memcmp`.
- Secret files with group/other permissions are rejected.
- All-zero raw keys are rejected as likely initialization mistakes.
- `--nonce-hex` now requires the explicit `--allow-unsafe-nonce` acknowledgement.
- Key and transcript state buffers are best-effort memory-locked during file operations.

### Corrections

- Corrected raw-key size documentation to 128 bytes / 256 hexadecimal characters.
- Removed the invalid `-fno-exceptions` build recommendation.
- Updated the inspector for v1/v2 metadata and more meaningful nonce-risk grouping.
