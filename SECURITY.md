# Security policy

## Project status

SymFrog-512 is experimental cryptographic research. It is not a standardized primitive and has not received broad independent cryptanalysis. A successful build and passing test suite establish implementation consistency, not cryptographic security.

For conventional production encryption, prefer a widely reviewed AEAD such as AES-GCM, ChaCha20-Poly1305, or Ascon through a maintained cryptographic library.

## Hardened format v2

The v2 implementation adds protocol-version separation, terminal ciphertext domain separation, authenticated KDF-profile metadata, explicit opt-in before honoring the SENSITIVE KDF profile, full stored-salt commitment, strict header parsing, authenticated-before-output decryption, symlink-resistant input opening, and no-overwrite output commits.

Legacy v1 decryption remains available for migration. New files are written only as v2.

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

Normal encryption generates a random 256-bit nonce. The deterministic `--nonce-hex` option is intended only for test-vector generation and requires `--allow-unsafe-nonce`. Reusing a nonce under the same key is unsafe.
