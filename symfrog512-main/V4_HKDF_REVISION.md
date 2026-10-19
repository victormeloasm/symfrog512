> **Historical v4 specification.** The current writer uses format v5-SIV. v4 remains decryptable, but the old v4 vector cannot be regenerated with the current writer.

# SymFrog-512 AEAD format v4: initialization erratum

Original file format versions 1 through 3 used `S0 = key XOR (0^768 || nonce) XOR domain_constants` (word-level constants). This implied a deterministically constructible related-key/nonce pair: `key2[96:128] = key1[96:128] XOR delta` and `nonce2 = nonce1 XOR delta` forced identical initial states, ciphertext and data tags. The legacy header authentication tags still differed. 

**v4 uses RFC 5869 HKDF-SHA-512.** The complete, byte-level, independently reproducible definition is in `README.md`; the 128-byte raw key OR the full output of the unchanged Argon2id derivation is the HKDF IKM, 32-byte nonce the salt, and ASCII label `SymFrog-512 AEAD v4 | P1024-v3 | initial state | HKDF-SHA-512` the info, without terminator. The HKDF expands to 128 bytes and maps them to 16 little-endian 64-bit words. P1024-v3 then processes the state unchanged.

Authenticated file header is still 152 bytes; v4 is selected by little-endian version 4 at bytes 8..11. All other serialization and password parameters are unchanged; hash mode still uses its v3 domain label and yields the same digests. New encryption emits only v4. Decryption of v1/v2/v3 follows the unchanged legacy path.

**Test vectors** (testing only, never use the public key as a secret):

- Raw key: bytes 0..127
- Nonce: bytes 0..31
- Plaintext: 4097 bytes, byte at offset i = i modulo 256
- AAD: `0102030405` (hex)
- v4 file SHA-256: `2f1ea307215670667eda1c23989d089afb5b112fc223aeef3beaa2289a7ba00a`
- v3 historical file SHA-256 (same inputs): `cd31ad7c2ee7be356b61dff7c831a157b6c8eaa0d5c8f43f1c5a6aa83c01bc36`
- v4 initial HKDF 128-byte hex: see `tests/fixtures/v4_hkdf_initial_state.hex`

**Security scope:** HKDF removes the specific XOR-cancellation identity; the test verifies lack of equality for related test pairs. It neither proves general related-key security nor eliminates all theoretical K/N collisions. The HKDF uses SHA-512 with 512-bit HMAC output, setting a ceiling on this extraction despite the nominal 1,024-bit raw key. P1024-v3 and the duplex construction remain experimental without independent cryptanalysis. Do not claim standard or certified AEAD security from these tests.
