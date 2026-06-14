# Changelog

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
