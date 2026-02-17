# 🐸 SymFrog-512

## High-Capacity Sponge-Based AEAD Cipher with 1024-bit Internal State

```{=html}
<p align="center">
```
`<img src="assets/logo.png" width="320" alt="SymFrog-512 Logo">`{=html}
```{=html}
</p>
```
SymFrog-512 is a high-capacity sponge duplex authenticated encryption
design built around a 1024-bit internal state. It is engineered with
conservative structural margins, authenticated metadata handling, atomic
file durability, and memory-safe practices.

This project provides a reference implementation written in modern C++
and is intended for research, experimentation, and high-assurance file
encryption scenarios.

Repository\
https://github.com/victormeloasm/symfrog512

Binary Release\
https://github.com/victormeloasm/symfrog512/releases/download/v1.0/symfrog512-linux-x86_64.tar.gz

License\
MIT

# Table of Contents

1.  Overview\
2.  Design Philosophy\
3.  Architecture\
4.  Security Model and Claims\
5.  Permutation Core P1024\
6.  AEAD Construction\
7.  File Format Specification\
8.  Key Handling Modes\
9.  Nonce Requirements\
10. Memory Hardening\
11. Atomic File Safety\
12. Build Instructions\
13. Usage Guide\
14. Test Suite\
15. Structural Validation Tool\
16. Threat Model\
17. Cryptographic Rationale\
18. Performance\
19. FAQ\
20. Roadmap\
21. License

# 1. Overview

SymFrog-512 is a sponge-based authenticated encryption construction
using a 1024-bit internal state partitioned into:

-   512-bit rate\
-   512-bit capacity

The construction follows a duplex model where associated data,
plaintext, and finalization phases are domain separated and
cryptographically bound.

Primary objectives:

-   Conservative structural margin\
-   Clear authenticated file format\
-   Deterministic reproducibility\
-   Crash-safe file handling\
-   Explicit secure memory practices

# 2. Design Philosophy

SymFrog-512 prioritizes:

-   Large internal state for structural safety margin\
-   Separation between rate and capacity domains\
-   Authenticated metadata before decryption\
-   Memory-hard password derivation\
-   Minimal implicit behavior\
-   Transparent and inspectable format

It does not claim standardization. It is a research-grade implementation
intended for evaluation and experimentation.

# 3. Architecture

Internal parameters:

-   State size: 1024 bits\
-   Rate: 512 bits\
-   Capacity: 512 bits\
-   Rounds: 24\
-   Nonce: 256 bits\
-   Tag: 256 bits

The duplex sponge model operates as:

Absorb Key\
Absorb Associated Data\
Encrypt or Decrypt Stream\
Finalize and Produce Tag

The capacity portion of the state is never directly exposed.

# 4. Security Model and Claims

SymFrog-512 targets:

-   Up to 256-bit effective security against generic AEAD forgery\
-   Up to 256-bit confidentiality under ideal permutation assumption\
-   2\^256 forgery bound from tag size

Important clarification:

Even though capacity is 512 bits, AEAD security is bounded by the
256-bit tag and generic attack models.

SymFrog-512 does not claim formal proof. Security relies on:

-   Structural sponge assumptions\
-   Absence of exploitable differential structure\
-   Nonce uniqueness\
-   Proper key management

# 5. Permutation Core P1024

The P1024 permutation runs for 24 structured rounds.

Each round includes:

-   Deterministic round constants derived from SHAKE256\
-   Full-width linear diffusion\
-   Non-linear bitslice mixing\
-   Symmetry breaking operations\
-   Fixed rotations\
-   Global word shuffle

Design goal is avalanche across the full 1024-bit state within a minimal
number of rounds.

# 6. AEAD Construction

SymFrog-512 implements Authenticated Encryption with Associated Data.

Properties:

-   Associated data authenticated but not encrypted\
-   Header authenticated independently\
-   Strict internal padding rule 10\*1\
-   No padding expansion visible in ciphertext file

Decryption verifies authentication before releasing plaintext.

# 7. File Format Specification

High-level structure:

Header\
Ciphertext\
Final Tag

Header contains:

-   Magic identifier\
-   Version\
-   Flags\
-   Salt when in password mode\
-   Nonce\
-   Ciphertext length\
-   Reserved fields\
-   Header authentication tag

Final 256-bit tag authenticates full encryption session.

# 8. Key Handling Modes

Password Mode:

-   Argon2id memory-hard derivation\
-   Salt stored in header\
-   Mitigates offline brute force

Raw Key Mode:

-   Direct high-entropy key input\
-   Intended for automation and controlled environments

Sensitive buffers:

-   Locked using sodium_mlock\
-   Wiped via secure zeroization

# 9. Nonce Requirements

Nonce must be unique per encryption under the same key.

Failure to enforce nonce uniqueness can compromise confidentiality in
stream-like constructions.

Tests may use deterministic nonce for reproducibility.

# 10. Memory Hardening

Security practices:

-   sodium_mlock to prevent swapping\
-   Explicit secure buffer wiping\
-   No secret material left in heap memory\
-   Controlled buffer lifetime

# 11. Atomic File Safety

Encryption writes:

Temporary file\
fsync\
Atomic rename

Prevents:

-   Partial writes\
-   Corrupted outputs on crash\
-   Power-loss inconsistencies

# 12. Build Instructions

Dependencies:

-   libsodium\
-   OpenSSL\
-   Clang or GCC supporting C++20

Ubuntu:

sudo apt install libsodium-dev libssl-dev clang lld

Build:

clang++ -std=c++20 -O3 -march=native -mtune=native -flto -fuse-ld=lld\
symfrog512.cpp -o symfrog512\
-lsodium -lssl -lcrypto

# 13. Usage Guide

Check help:

./symfrog512 --help

Encrypt example:

./symfrog512 encrypt input.bin output.syf --password "pass" --ad
"context"

Decrypt example:

./symfrog512 decrypt output.syf recovered.bin --password "pass" --ad
"context"

Raw key mode:

./symfrog512 encrypt input.bin output.syf --raw-key HEXKEY

# 14. Test Suite

Run:

./symfrog512 --test-all

Covers:

-   Zero-length files\
-   Boundary sizes\
-   Large file sizes\
-   Wrong password detection\
-   Wrong key detection\
-   Tampered ciphertext\
-   Tampered header\
-   Truncation detection

# 15. Structural Validation Tool

Optional Python inspection script validates:

-   Header structure\
-   Field consistency\
-   Tag placement\
-   Ciphertext length integrity

Does not decrypt data.

# 16. Threat Model

Protected:

-   Passive attacker reading ciphertext\
-   Active attacker modifying ciphertext\
-   Offline brute force mitigated by Argon2id

Out of scope:

-   Compromised endpoint\
-   Malicious OS\
-   Physical memory extraction

# 17. Cryptographic Rationale

Capacity 512 bits provides conservative internal margin.

Tag 256 bits bounds forgery probability.

Large state increases resistance to multi-target generic attacks.

Duplex construction avoids state exposure prior to finalization.

Header authentication prevents metadata manipulation.

# 18. Performance

Approximate values on modern x86_64:

-   Sub-microsecond permutation latency\
-   Efficient streaming throughput\
-   Single-core optimized build

# 19. FAQ

Is this standardized\
No

Is it stronger than AES-GCM\
Not in terms of standardization maturity

Why 1024-bit state\
Conservative margin and structural separation

# 20. Roadmap

Planned improvements:

-   Formal specification document\
-   Published test vectors\
-   Reduced-round analysis\
-   CI reproducible builds\
-   Expanded benchmarking

# 21. License

MIT License

Copyright 2026 Victor Duarte Melo

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files to deal in the
Software without restriction.
