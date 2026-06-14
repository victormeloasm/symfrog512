# SymFrog Full Test Checklist

## Implemented internally in `symfrog_full_suite.cpp`
- Known-answer style roundtrip and tamper tests via upstream `run_self_tests`
- Permutation avalanche by round
- Strict Avalanche Criterion sample
- Bit Independence Criterion sample
- Bit balance
- Byte frequency / chi-square
- Linearity distance smoke test
- Fixed point / near-fixed-point search smoke test
- Short cycle smoke test
- Zero-state orbit trace
- Symmetry smoke tests
- Low-weight input propagation
- Integral-balance smoke test
- Differential smoke test
- Hash determinism
- Hash avalanche
- Hash bit balance
- Hash byte frequency
- Hash collision smoke test on 128-bit prefixes
- Hash near-collision smoke test
- Hash second-preimage smoke test
- AEAD nonce-reuse demo
- AEAD wrong-AD / wrong-key matrix
- Upstream benchmarks

## Included as external-tool drivers or build helpers
- NIST STS driver
- Dieharder driver
- PractRand driver
- Sanitizer build script
- libFuzzer build script
- AFL++ build stub

## Listed for manual / research follow-up
- Differential cryptanalysis
- Truncated differential cryptanalysis
- Impossible differential cryptanalysis
- Differential-linear cryptanalysis
- Boomerang / rectangle analysis
- Linear cryptanalysis / linear hull search
- Integral / zero-sum / division-property analysis
- Invariant subspace search
- Algebraic / SAT / MILP trail search
- Collision / chosen-prefix / multicollision / herding attacks
- Preimage / second-preimage advanced attacks
- Indifferentiability proof
- Security reductions / multi-user bounds
- Constant-time audit
- Cache / branch / microarchitectural side-channel analysis
- DPA / SPA / EM analysis
- Fault injection / glitching
- Formal verification
