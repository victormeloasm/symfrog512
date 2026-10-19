# Security policy

## Project status

SymFrog-512 is experimental cryptographic research. It is not a standardized primitive and has not received broad independent cryptanalysis. A successful build and passing test suite establish implementation consistency, not cryptographic security.

For conventional production encryption, prefer a widely reviewed AEAD such as AES-GCM, ChaCha20-Poly1305, or Ascon through a maintained cryptographic library.

## P1024-v3 and historical non-bijectivity

The previous four-word parallel χ was not injective, therefore the old P1024-v2 core was not a permutation. The v3 nonlinear layer now has a constructive inverse, as does every other round operation. Built-in tests check reversal for 1,154 full states, including each of the 1,024 basis bits. **This does not establish cryptographic security or justify adopting ideal-permutation bounds.**

Versions v1/v2/v3/v4 are supported for decryption/migration; new encryptions use experimental format v5 with a synthetic IV and HKDF-SHA-512 initialization. FrogHash-512 changed at the P1024-v3 transition from the historical P1024-v2. It is unchanged between AEAD formats v3, v4, and v5.

## Hardened format foundation (v2/v3)

The v2+ implementation adds protocol-version separation, terminal ciphertext domain separation, authenticated KDF-profile metadata, explicit opt-in before honoring the SENSITIVE KDF profile, full stored-salt commitment, strict header parsing, authenticated-before-output decryption, symlink-resistant input opening, and no-overwrite output commits.

Legacy v1/v2/v3/v4 decryption remains available for migration. New files are written only as v5.

## AEAD v4 key/nonce design status

Formats v1/v2/v3 had an exact XOR-related key/nonce state equivalence. Format v4 replaces that AEAD initialization with HKDF-SHA-512 and removes this demonstrated identity. The P1024-v3 permutation and FrogHash are unchanged. This patch does not prove related-key security or nonce-misuse resistance, nor does it provide a security guarantee stronger than the SHA-512-based derivation, capacity, or the independently unaudited construction. Read `V4_HKDF_REVISION.md` and `V5_SIV_DESIGN_AND_TESTS.md` before citing cryptographic claims.

## v5 experimental SIV-style scheme

The default v5 writer derives a synthetic IV from the keyed complete plaintext, AAD and authenticated header metadata before encryption. Repeating a public nonce under the same key with *different* plaintext no longer trivially reuses the initial keystream. The v5 file has two public 32-byte values: header.salt (public nonce, also password KDF salt) and header.nonce (synthetic IV). Same key/plaintext/public nonce/AAD/metadata produces the same ciphertext and reveals equality. Correctness and small-sample testing do **not** establish any provable misuse-resistance bound for the custom duplex. Key derivation and MAC depend on SHA-512; the underlying P1024-v3 and output transform remain custom and unaudited. The SplitMix64 finalizer within output_transform_rate is mathematically invertible; it is not itself a one-way primitive. Broad differential/linear, forgery and side-channel analysis remain open.

## Reporting

Reports are especially welcome for:

- permutation distinguishers, differential or linear trails;
- state-recovery, forgery, nonce-reuse, or related-key weaknesses;
- transcript ambiguity or domain-separation problems;
- parsing, integer, file-system race, or side-channel vulnerabilities;
- mismatches between the specification, code, and test vectors.

A useful report should include the affected version, platform/compiler, minimal reproduction, expected result, actual result, and any proof-of-concept limited to local test data.

## Secret handling

Prefer `--pass-prompt`, `--pass-file`, and `--key-file`. Legacy `--pass` and `--key-hex` can expose secrets through argv and shell history. Secret files are rejected unless their mode is `0600` or stricter. All-zero raw keys are rejected as probable setup errors.

Protect raw keys and passphrase files with restrictive permissions and backups. Losing the only key means losing the ciphertext permanently.


## Nonce discipline

Normal v5 encryption generates a random 256-bit **public nonce** in header.salt and derives the **synthetic IV** in header.nonce from the complete keyed plaintext transcript. The deterministic `--nonce-hex` option is intended only for test vectors and requires `--allow-unsafe-nonce`. For v1–v4, reuse of a nonce under a key is unsafe. For experimental v5, identical messages and metadata produce identical ciphertext when the public nonce is reused; use a fresh random nonce by default.
