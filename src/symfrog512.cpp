/*
 * SymFrog-512 (FROGSPONGE-1024 v2) - Reference Implementation (Paranoid)
 * AEAD (sponge duplex) with:
 *   - State 1024 bits (16x u64), Rate 512 bits, Capacity 512 bits
 *   - Key 1024 bits (raw key) OR passphrase via Argon2id (libsodium)
 *   - Nonce 256 bits
 *   - Tag 256 bits
 * Hash mode:
 *   - FrogHash-512 using the same permutation core
 *
 * CLI:
 *   symfrog512 --help
 *   symfrog512 --test-all
 *   symfrog512 --benchmark
 *   symfrog512 enc  <in> <out> [--pass <pw> | --key-hex <2048-bit-hex>] [--ad <hex>] [--nonce-hex <64-hex>]
 *   symfrog512 dec  <in> <out> [--pass <pw> | --key-hex <2048-bit-hex>] [--ad <hex>]
 *   symfrog512 hash <in> [--out <digest_hex_file>]
 *
 * Notes:
 *   - Little-endian is the canonical format for bytes<->u64.
 *   - Atomic write: outputs are written to "<out>.tmp.<pid>" then fsync() then rename().
 *   - Directory fsync is attempted for durability.
 *
 * Build (Ubuntu):
 *   clang++ -std=c++23 -O3 -march=native -mtune=native -flto -fno-exceptions -fno-rtti symfrog512.cpp -o symfrog512 -lsodium -lcrypto
 *
 * License: MIT (as per HyperFrog artifacts policy)
 */

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>

#include <string>
#include <vector>
#include <algorithm>
#include <stdexcept>
#include <bit>

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

#include <time.h>

#include <sodium.h>
#include <openssl/evp.h>

#ifndef O_DIRECTORY
#define O_DIRECTORY 0200000
#endif

// -------------------- Parameters --------------------
static constexpr size_t STATE_WORDS   = 16;      // 1024 bits
static constexpr size_t RATE_WORDS    = 8;       // 512 bits
static constexpr size_t CAP_WORDS     = 8;       // 512 bits
[[maybe_unused]] static constexpr size_t STATE_BYTES   = 128;
static constexpr size_t RATE_BYTES    = 64;
[[maybe_unused]] static constexpr size_t CAP_BYTES     = 64;
static constexpr size_t KEY_BYTES     = 128;     // 1024-bit key
static constexpr size_t NONCE_BYTES   = 32;      // 256-bit nonce
static constexpr size_t TAG_BYTES     = 32;      // 256-bit tag
static constexpr size_t SALT_BYTES    = 32;      // 256-bit salt (for Argon2id)

static constexpr uint64_t MASK64      = 0xFFFFFFFFFFFFFFFFULL;
static constexpr int ROUNDS           = 24;

// Rotation constants (final decision):
//  - even indices: 19
//  - odd indices:  61  (coprime with 64, avoids sub-cycle diffusion)
[[maybe_unused]] static constexpr uint8_t ROT_CONST[STATE_WORDS] = {
    19,61,19,61,19,61,19,61,19,61,19,61,19,61,19,61
};

// P-Box permutation (word shuffle)


// Domain separation constants (u64)
static constexpr uint64_t DS_AD  = 0xA0ULL;
static constexpr uint64_t DS_CT  = 0xC0ULL;
static constexpr uint64_t DS_TAG = 0xF0ULL;

static constexpr uint64_t KICK_C = 0x9E3779B97F4A7C15ULL;

// File header
static constexpr uint8_t  MAGIC[8] = {'S','Y','M','F','R','O','G','1'};
static constexpr uint32_t VERSION  = 0x00000001U;

// Header layout (all little-endian):
//   magic[8] | version(u32) | flags(u32) | salt[32] | nonce[32] | ct_len(u64) | reserved[32] | header_tag[32]
// Total = 8 +4+4 +32+32+8+32+32 = 152 bytes
static constexpr size_t HEADER_BYTES = 152;
static constexpr size_t HDR_RESERVED_BYTES = 32;

static constexpr uint32_t FLAG_KEY_DERIVED = 1u << 0; // Argon2id used

// -------------------- Utilities --------------------
static inline uint64_t rotl64(uint64_t x, uint32_t k) {
    return (k == 0) ? x : ((x << k) | (x >> (64 - k)));
}

static inline uint64_t load64_le(const uint8_t* p) {
    return (uint64_t)p[0]
        | ((uint64_t)p[1] << 8)
        | ((uint64_t)p[2] << 16)
        | ((uint64_t)p[3] << 24)
        | ((uint64_t)p[4] << 32)
        | ((uint64_t)p[5] << 40)
        | ((uint64_t)p[6] << 48)
        | ((uint64_t)p[7] << 56);
}

static inline void store64_le(uint8_t* p, uint64_t x) {
    p[0] = (uint8_t)(x);
    p[1] = (uint8_t)(x >> 8);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 24);
    p[4] = (uint8_t)(x >> 32);
    p[5] = (uint8_t)(x >> 40);
    p[6] = (uint8_t)(x >> 48);
    p[7] = (uint8_t)(x >> 56);
}

static inline void store32_le(uint8_t* p, uint32_t x) {
    p[0] = (uint8_t)(x);
    p[1] = (uint8_t)(x >> 8);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 24);
}

static inline void secure_zero(void* p, size_t n) {
    if (p && n) sodium_memzero(p, n);
}

static inline void try_mlock(void* p, size_t n, bool quiet) {
    if (!p || !n) return;
    if (sodium_mlock(p, n) != 0) {
        if (!quiet) {
            std::fprintf(stderr, "SymFrog: warning: sodium_mlock failed (continuing): %s\n", std::strerror(errno));
        }
    }
}

static inline void try_munlock(void* p, size_t n) {
    if (!p || !n) return;
    (void)sodium_munlock(p, n);
}

struct MlockGuard {
    void* p;
    size_t n;
    MlockGuard(void* p_, size_t n_, bool quiet) : p(p_), n(n_) { try_mlock(p, n, quiet); }
    ~MlockGuard() { try_munlock(p, n); }
    MlockGuard(const MlockGuard&) = delete;
    MlockGuard& operator=(const MlockGuard&) = delete;
};

static inline void die_errno(const char* msg) {
    std::fprintf(stderr, "SymFrog error: %s (errno=%d: %s)\n", msg, errno, std::strerror(errno));
}

static inline void die_msg(const char* msg) {
    std::fprintf(stderr, "SymFrog error: %s\n", msg);
}

static bool write_all(int fd, const uint8_t* buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = ::write(fd, buf + off, n - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        // write() returning 0 on a regular file would otherwise cause an infinite loop.
        if (w == 0) return false;
        off += (size_t)w;
    }
    return true;
}

static bool read_all(int fd, uint8_t* buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = ::read(fd, buf + off, n - off);
        if (r < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (r == 0) return false;
        off += (size_t)r;
    }
    return true;
}

static bool read_some(int fd, uint8_t* buf, size_t want, size_t& got) {
    got = 0;
    while (true) {
        ssize_t r = ::read(fd, buf, want);
        if (r < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        got = (size_t)r;
        return true;
    }
}

static bool fsync_dir_of_path(const char* path) {
    const char* slash = std::strrchr(path, '/');
    std::string dir;
    if (!slash) dir = ".";
    else dir.assign(path, static_cast<size_t>(slash - path));
    int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY);
    if (dfd < 0) return false;
    bool ok = (::fsync(dfd) == 0);
    ::close(dfd);
    return ok;
}

static bool hex_to_bytes(const char* hex, std::vector<uint8_t>& out) {
    out.clear();
    size_t n = std::strlen(hex);
    if (n % 2 != 0) return false;
    out.reserve(n/2);
    auto hexval = [](char c)->int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };
    for (size_t i = 0; i < n; i += 2) {
        int hi = hexval(hex[i]);
        int lo = hexval(hex[i+1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back((uint8_t)((hi << 4) | lo));
    }
    return true;
}

static std::string bytes_to_hex(const uint8_t* b, size_t n) {
    static const char* hexd = "0123456789abcdef";
    std::string s;
    s.resize(n*2);
    for (size_t i = 0; i < n; i++) {
        s[2*i]   = hexd[(b[i] >> 4) & 0xF];
        s[2*i+1] = hexd[(b[i]     ) & 0xF];
    }
    return s;
}

[[maybe_unused]] static uint64_t load_u64_le_from_vec(const std::vector<uint8_t>& v, size_t off) {
    return load64_le(v.data() + off);
}

// -------------------- RC Generation (SHAKE256) --------------------
static void gen_round_constants(uint64_t RC[ROUNDS][CAP_WORDS]) {
    // Deterministic round constants derived as:
    //   RC[r] = first 64 bytes of SHAKE256("SymFrog-rc-v1" || LE32(r))
    // IMPORTANT: Keep this exactly stable across versions, or ciphertexts become non-decryptable.
    static const uint8_t label[] = "SymFrog-rc-v1";

    EVP_MD_CTX* base = EVP_MD_CTX_new();
    if (!base) std::abort();
    if (EVP_DigestInit_ex(base, EVP_shake256(), nullptr) != 1) std::abort();
    if (EVP_DigestUpdate(base, label, sizeof(label) - 1) != 1) std::abort();

    for (uint32_t r = 0; r < ROUNDS; r++) {
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        if (!mdctx) std::abort();
        if (EVP_MD_CTX_copy_ex(mdctx, base) != 1) std::abort();

        uint8_t ctr[4];
        store32_le(ctr, r);

        uint8_t out[CAP_WORDS * 8];
        if (EVP_DigestUpdate(mdctx, ctr, sizeof(ctr)) != 1) std::abort();
        if (EVP_DigestFinalXOF(mdctx, out, sizeof(out)) != 1) std::abort();

        for (size_t j = 0; j < CAP_WORDS; j++) {
            RC[r][j] = load64_le(out + 8*j);
        }

        secure_zero(ctr, sizeof(ctr));
        secure_zero(out, sizeof(out));
        EVP_MD_CTX_free(mdctx);
    }
    EVP_MD_CTX_free(base);
}

// -------------------- Core Permutation P1024-v2 --------------------
static inline void chi_layer(uint64_t S[STATE_WORDS]) {
    uint64_t T[STATE_WORDS];
    for (size_t i = 0; i < STATE_WORDS; i++) T[i] = S[i];

    for (size_t g = 0; g < STATE_WORDS; g += 4) {
        uint64_t t0 = T[g+0], t1 = T[g+1], t2 = T[g+2], t3 = T[g+3];
        S[g+0] ^= (~t1) & t2;
        S[g+1] ^= (~t2) & t3;
        S[g+2] ^= (~t3) & t0;
        S[g+3] ^= (~t0) & t1;
    }
    secure_zero(T, sizeof(T));
}

static inline void kick_layer(uint64_t S[STATE_WORDS]) {
    // Phase A: even -> odd
    for (size_t i = 0; i < STATE_WORDS; i += 2) {
        uint64_t m = S[i] | 1ULL;
        uint64_t kick = (S[i] * m) & MASK64;
        S[(i + 1) & 15] ^= kick;
    }
    // Phase B: odd -> even
    for (size_t i = 1; i < STATE_WORDS; i += 2) {
        uint64_t m = S[i] | 1ULL;
        uint64_t kick = (S[i] * (m ^ KICK_C)) & MASK64;
        uint64_t val  = rotl64(kick, 23);
        S[(i + 1) & 15] ^= val;
    }
}

static inline void rotate_shuffle(uint64_t S[STATE_WORDS]) {
    // Rotate (fixed constants)
    S[0]  = rotl64(S[0],  19); S[1]  = rotl64(S[1],  61);
    S[2]  = rotl64(S[2],  19); S[3]  = rotl64(S[3],  61);
    S[4]  = rotl64(S[4],  19); S[5]  = rotl64(S[5],  61);
    S[6]  = rotl64(S[6],  19); S[7]  = rotl64(S[7],  61);
    S[8]  = rotl64(S[8],  19); S[9]  = rotl64(S[9],  61);
    S[10] = rotl64(S[10], 19); S[11] = rotl64(S[11], 61);
    S[12] = rotl64(S[12], 19); S[13] = rotl64(S[13], 61);
    S[14] = rotl64(S[14], 19); S[15] = rotl64(S[15], 61);

    // Hard-unrolled shuffle (P_BOX):
    // N[0]=S0, N[1]=S13, N[2]=S10, N[3]=S7, N[4]=S4, N[5]=S1, N[6]=S14, N[7]=S11,
    // N[8]=S8, N[9]=S5, N[10]=S2, N[11]=S15, N[12]=S12, N[13]=S9, N[14]=S6, N[15]=S3
    uint64_t s0=S[0], s1=S[1], s2=S[2], s3=S[3], s4=S[4], s5=S[5], s6=S[6], s7=S[7];
    uint64_t s8=S[8], s9=S[9], s10=S[10], s11=S[11], s12=S[12], s13=S[13], s14=S[14], s15=S[15];

    S[0]=s0;   S[1]=s13; S[2]=s10; S[3]=s7;
    S[4]=s4;   S[5]=s1;  S[6]=s14; S[7]=s11;
    S[8]=s8;   S[9]=s5;  S[10]=s2; S[11]=s15;
    S[12]=s12; S[13]=s9; S[14]=s6; S[15]=s3;
}

static inline void mixer_layer(uint64_t S[STATE_WORDS]) {
    // Early diffusion: rate absorbs capacity immediately
    for (size_t i = 0; i < RATE_WORDS; i++) {
        S[i] ^= S[i + RATE_WORDS];
    }
}

static void permute_p1024_v2(uint64_t* __restrict__ S, const uint64_t RC[ROUNDS][CAP_WORDS]) {
    // 24 rounds
    for (int r = 0; r < ROUNDS; r++) {
        // AddRoundConstants: capacity only
        for (size_t j = 0; j < CAP_WORDS; j++) {
            S[RATE_WORDS + j] ^= RC[r][j];
        }
        // Mixer
        mixer_layer(S);
        // Chi
        chi_layer(S);
        // Kick
        kick_layer(S);
        // Rotate & Shuffle
        rotate_shuffle(S);
    }
}

// -------------------- Sponge helpers --------------------
static inline void xor_rate(uint64_t S[STATE_WORDS], const uint8_t block[RATE_BYTES]) {
    for (size_t i = 0; i < RATE_WORDS; i++) {
        S[i] ^= load64_le(block + 8*i);
    }
}

[[maybe_unused]] static inline void extract_rate(uint8_t out[RATE_BYTES], const uint64_t S[STATE_WORDS]) {
    for (size_t i = 0; i < RATE_WORDS; i++) {
        store64_le(out + 8*i, S[i]);
    }
}

// Output transform (does NOT modify state): prevents trivial rate-state exposure.
// Uses capacity words as a one-way mixer into the emitted rate bytes.
static inline void output_transform_rate(uint8_t out[RATE_BYTES], const uint64_t S[STATE_WORDS]) {
    for (size_t i = 0; i < RATE_WORDS; i++) {
        uint64_t x = S[i];
        uint64_t a = S[RATE_WORDS + i];
        uint64_t b = S[RATE_WORDS + ((i + 3) & 7)];
        uint64_t t = x ^ rotl64(a, 17) ^ rotl64(b, 41) ^ (0x9E3779B97F4A7C15ULL * (uint64_t)(i + 1));
        // SplitMix64 finalizer (avalanche)
        t ^= (t >> 30);
        t *= 0xBF58476D1CE4E5B9ULL;
        t ^= (t >> 27);
        t *= 0x94D049BB133111EBULL;
        t ^= (t >> 31);
        store64_le(out + 8*i, t);
    }
}

static inline void xor_byte_rate(uint64_t S[STATE_WORDS], size_t idx, uint8_t val) {
    // XOR a byte into rate, little-endian within u64 words
    size_t w = idx >> 3;
    size_t b = idx & 7;
    uint64_t m = (uint64_t)val << (8*b);
    S[w] ^= m;
}

static void absorb_rate_partial_and_pad(uint64_t S[STATE_WORDS], const uint8_t* data, size_t len, const uint64_t RC[ROUNDS][CAP_WORDS]) {
    // Absorb remaining bytes (len < RATE_BYTES)
    for (size_t i = 0; i < len; i++) {
        xor_byte_rate(S, i, data[i]);
    }
    // Padding 10*1
    xor_byte_rate(S, len, 0x80);
    xor_byte_rate(S, RATE_BYTES - 1, 0x01);
    permute_p1024_v2(S, RC);
}

[[maybe_unused]] static void absorb_full_blocks(uint64_t S[STATE_WORDS], int fd, uint64_t total_bytes, const uint64_t RC[ROUNDS][CAP_WORDS],
                               uint8_t domain_byte) {
    // Absorb total_bytes from fd, in full 64-byte blocks with buffered IO.
    // This is used for AAD (AD).
    static constexpr size_t CHUNK = 1 << 20; // 1 MiB
    std::vector<uint8_t> buf(CHUNK + RATE_BYTES);

    size_t tail_len = 0;
    uint64_t consumed = 0;

    while (consumed < total_bytes) {
        size_t want = (size_t)std::min<uint64_t>((uint64_t)CHUNK, total_bytes - consumed);
        size_t got = 0;
        if (!read_some(fd, buf.data() + tail_len, want, got)) {
            throw std::runtime_error("read error");
        }
        if (got == 0) throw std::runtime_error("unexpected EOF");

        consumed += got;
        size_t total = tail_len + got;

        size_t full = total / RATE_BYTES;
        size_t proc_bytes = full * RATE_BYTES;

        // Process full blocks, in-place.
        for (size_t off = 0; off < proc_bytes; off += RATE_BYTES) {
            xor_rate(S, buf.data() + off);
            S[15] ^= domain_byte;
            permute_p1024_v2(S, RC);
        }

        // Move tail
        tail_len = total - proc_bytes;
        if (tail_len) {
            std::memmove(buf.data(), buf.data() + proc_bytes, tail_len);
        }
    }

    // Absorb tail with pad (even if tail_len == 0, we still need a padding block)
    // We follow sponge convention: always pad at end of AD.
    absorb_rate_partial_and_pad(S, buf.data(), tail_len, RC);
}

static void absorb_ad_bytes(uint64_t S[STATE_WORDS], const uint8_t* ad, size_t ad_len, const uint64_t RC[ROUNDS][CAP_WORDS]) {
    // Memory absorb for AD (for header-tag / unit tests)
    size_t off = 0;
    while (off + RATE_BYTES <= ad_len) {
        xor_rate(S, ad + off);
        S[15] ^= DS_AD;
        permute_p1024_v2(S, RC);
        off += RATE_BYTES;
    }
    size_t rem = ad_len - off;
    // absorb remaining with padding
    // domain separation is also applied per block; for the final padded block we keep DS_AD too.
    // We implement by XORing DS_AD before final permutation.
    for (size_t i = 0; i < rem; i++) xor_byte_rate(S, i, ad[off+i]);
    xor_byte_rate(S, rem, 0x80);
    xor_byte_rate(S, RATE_BYTES - 1, 0x01);
    S[15] ^= DS_AD;
    permute_p1024_v2(S, RC);
}

// Output Transform: tag extraction uses additional permute barrier
static void finalize_tag(uint64_t S[STATE_WORDS], const uint64_t RC[ROUNDS][CAP_WORDS], uint8_t tag[TAG_BYTES]) {
    S[15] ^= DS_TAG;
    permute_p1024_v2(S, RC);
    uint8_t rate[RATE_BYTES];
    output_transform_rate(rate, S);
    std::memcpy(tag, rate, TAG_BYTES);
    secure_zero(rate, sizeof(rate));
}

// -------------------- Keying --------------------
static void init_state_with_key_nonce(uint64_t S[STATE_WORDS],
                                      const uint8_t key[KEY_BYTES],
                                      const uint8_t nonce[NONCE_BYTES]) {
    // S = key (16 u64 LE)
    for (size_t i = 0; i < STATE_WORDS; i++) {
        S[i] = load64_le(key + 8*i);
    }
    // XOR nonce into last 4 words
    S[12] ^= load64_le(nonce + 0);
    S[13] ^= load64_le(nonce + 8);
    S[14] ^= load64_le(nonce + 16);
    S[15] ^= load64_le(nonce + 24);

    // Domain separation ID
    // "SYMFROG-512" / "AEAD-v1"
    S[8]  ^= 0x53594D46524F472DULL; // "SYMFROG-"
    S[9]  ^= 0x3531322D41454144ULL; // "512-AEAD"
    S[10] ^= 0x2D76312D00000000ULL; // "-v1-"
    S[11] ^= 0x0000000000000001ULL;
}

static void kdf_argon2id(uint8_t out_key[KEY_BYTES],
                         const char* pass,
                         const uint8_t salt[SALT_BYTES],
                         bool paranoid) {
    // Paranoid means use libsodium SENSITIVE limits
    // Default uses MODERATE to keep runtime reasonable.
    unsigned long long ops = paranoid ? crypto_pwhash_OPSLIMIT_SENSITIVE
                                      : crypto_pwhash_OPSLIMIT_MODERATE;
    size_t mem = paranoid ? crypto_pwhash_MEMLIMIT_SENSITIVE
                          : crypto_pwhash_MEMLIMIT_MODERATE;

    if (crypto_pwhash(out_key, KEY_BYTES,
                      pass, std::strlen(pass),
                      salt,
                      ops, mem,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw std::runtime_error("Argon2id failed (out of memory?)");
    }
}

static void random_bytes(uint8_t* p, size_t n) {
    randombytes_buf(p, n);
}

// -------------------- Header (Authenticated) --------------------
struct Header {
    uint8_t  magic[8];
    uint32_t version;
    uint32_t flags;
    uint8_t  salt[SALT_BYTES];
    uint8_t  nonce[NONCE_BYTES];
    uint64_t ct_len;
    uint8_t  reserved[HDR_RESERVED_BYTES];
    uint8_t  header_tag[TAG_BYTES];
};

static void header_serialize(uint8_t out[HEADER_BYTES], const Header& h) {
    size_t off = 0;
    std::memcpy(out + off, h.magic, 8); off += 8;
    // version, flags, ct_len little-endian
    out[off+0] = (uint8_t)(h.version);
    out[off+1] = (uint8_t)(h.version >> 8);
    out[off+2] = (uint8_t)(h.version >> 16);
    out[off+3] = (uint8_t)(h.version >> 24);
    off += 4;
    out[off+0] = (uint8_t)(h.flags);
    out[off+1] = (uint8_t)(h.flags >> 8);
    out[off+2] = (uint8_t)(h.flags >> 16);
    out[off+3] = (uint8_t)(h.flags >> 24);
    off += 4;
    std::memcpy(out + off, h.salt, SALT_BYTES); off += SALT_BYTES;
    std::memcpy(out + off, h.nonce, NONCE_BYTES); off += NONCE_BYTES;
    // ct_len
    out[off+0] = (uint8_t)(h.ct_len);
    out[off+1] = (uint8_t)(h.ct_len >> 8);
    out[off+2] = (uint8_t)(h.ct_len >> 16);
    out[off+3] = (uint8_t)(h.ct_len >> 24);
    out[off+4] = (uint8_t)(h.ct_len >> 32);
    out[off+5] = (uint8_t)(h.ct_len >> 40);
    out[off+6] = (uint8_t)(h.ct_len >> 48);
    out[off+7] = (uint8_t)(h.ct_len >> 56);
    off += 8;
    std::memcpy(out + off, h.reserved, HDR_RESERVED_BYTES); off += HDR_RESERVED_BYTES;
    std::memcpy(out + off, h.header_tag, TAG_BYTES); off += TAG_BYTES;

    if (off != HEADER_BYTES) std::abort();
}

static bool header_parse(Header& h, const uint8_t in[HEADER_BYTES]) {
    size_t off = 0;
    std::memcpy(h.magic, in + off, 8); off += 8;

    auto rd_u32 = [&](uint32_t& v) {
        v = (uint32_t)in[off]
          | ((uint32_t)in[off+1] << 8)
          | ((uint32_t)in[off+2] << 16)
          | ((uint32_t)in[off+3] << 24);
        off += 4;
    };
    rd_u32(h.version);
    rd_u32(h.flags);

    std::memcpy(h.salt, in + off, SALT_BYTES); off += SALT_BYTES;
    std::memcpy(h.nonce, in + off, NONCE_BYTES); off += NONCE_BYTES;

    h.ct_len = (uint64_t)in[off]
             | ((uint64_t)in[off+1] << 8)
             | ((uint64_t)in[off+2] << 16)
             | ((uint64_t)in[off+3] << 24)
             | ((uint64_t)in[off+4] << 32)
             | ((uint64_t)in[off+5] << 40)
             | ((uint64_t)in[off+6] << 48)
             | ((uint64_t)in[off+7] << 56);
    off += 8;

    std::memcpy(h.reserved, in + off, HDR_RESERVED_BYTES); off += HDR_RESERVED_BYTES;
    std::memcpy(h.header_tag, in + off, TAG_BYTES); off += TAG_BYTES;
    return (off == HEADER_BYTES);
}


// Header-tag (keyed) is computed as:
//   HeaderTag = Tag32(  Init(key, nonce) ; Absorb(domain || header_without_tag || AAD) ; Finalize(D S_HDRTAG) )
// This gives early-reject for wrong key/AAD or tampered header (without writing output).
static constexpr uint8_t  DS_HDR    = 0xB0;
static constexpr uint8_t  DS_HDRTAG = 0xB1;

static void absorb_bytes_domain(uint64_t S[STATE_WORDS], const uint8_t* msg, size_t msg_len,
                                const uint64_t RC[ROUNDS][CAP_WORDS], uint8_t domain) {
    size_t off = 0;
    while (off + RATE_BYTES <= msg_len) {
        xor_rate(S, msg + off);
        S[15] ^= domain;
        permute_p1024_v2(S, RC);
        off += RATE_BYTES;
    }
    size_t rem = msg_len - off;
    for (size_t i = 0; i < rem; i++) xor_byte_rate(S, i, msg[off+i]);
    xor_byte_rate(S, rem, 0x80);
    xor_byte_rate(S, RATE_BYTES - 1, 0x01);
    S[15] ^= domain;
    permute_p1024_v2(S, RC);
}

static void finalize_tag_domain(uint64_t S[STATE_WORDS], const uint64_t RC[ROUNDS][CAP_WORDS], uint8_t domain, uint8_t tag[TAG_BYTES]) {
    S[15] ^= domain;
    permute_p1024_v2(S, RC);
    uint8_t rate[RATE_BYTES];
    output_transform_rate(rate, S);
    std::memcpy(tag, rate, TAG_BYTES);
    secure_zero(rate, sizeof(rate));
}

// Forward decl (needed because compute_header_tag_keyed uses it)
static void symfrog_init(uint64_t S[STATE_WORDS],
                         const uint8_t key[KEY_BYTES],
                         const uint8_t nonce[NONCE_BYTES],
                         const uint64_t RC[ROUNDS][CAP_WORDS]);

static void compute_header_tag_keyed(const uint64_t RC[ROUNDS][CAP_WORDS],
                                     const uint8_t key[KEY_BYTES],
                                     const uint8_t nonce[NONCE_BYTES],
                                     const Header& h_wo_tag,
                                     const uint8_t* ad, size_t ad_len,
                                     uint8_t out_tag[TAG_BYTES],
                                     bool quiet)
{
    static const uint8_t dom[] = {'S','Y','M','F','R','O','G','-','H','D','R','T','A','G','-','v','1'};

    // header without header_tag bytes
    uint8_t hdr_no_tag[HEADER_BYTES];
    Header tmp = h_wo_tag;
    std::memset(tmp.header_tag, 0, TAG_BYTES);
    header_serialize(hdr_no_tag, tmp);

    std::vector<uint8_t> buf;
    buf.reserve(sizeof(dom) + HEADER_BYTES + ad_len);
    buf.insert(buf.end(), dom, dom + sizeof(dom));
    buf.insert(buf.end(), hdr_no_tag, hdr_no_tag + HEADER_BYTES);
    if (ad && ad_len) buf.insert(buf.end(), ad, ad + ad_len);

    alignas(64) uint64_t S[STATE_WORDS];
    MlockGuard lock_state(S, sizeof(S), quiet);
    symfrog_init(S, key, nonce, RC);
    absorb_bytes_domain(S, buf.data(), buf.size(), RC, DS_HDR);
    finalize_tag_domain(S, RC, DS_HDRTAG, out_tag);

    secure_zero(S, sizeof(S));
    secure_zero(hdr_no_tag, sizeof(hdr_no_tag));
    secure_zero(buf.data(), buf.size());
}

// Constant-time tag compare
static bool ct_memeq(const uint8_t* a, const uint8_t* b, size_t n) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

// -------------------- SymFrog AEAD (streaming) --------------------
static void symfrog_init(uint64_t* __restrict__ S, const uint8_t key[KEY_BYTES], const uint8_t nonce[NONCE_BYTES],
                         const uint64_t RC[ROUNDS][CAP_WORDS]) {
    init_state_with_key_nonce(S, key, nonce);
    permute_p1024_v2(S, RC);
}

static void symfrog_absorb_ad_mem(uint64_t S[STATE_WORDS], const uint8_t* ad, size_t ad_len,
                                  const uint64_t RC[ROUNDS][CAP_WORDS]) {
    if (ad && ad_len) {
        absorb_ad_bytes(S, ad, ad_len, RC);
    } else {
        // Even with empty AD, we domain-separate once with padding
        absorb_ad_bytes(S, nullptr, 0, RC);
    }
}

static void symfrog_encrypt_stream(uint64_t S[STATE_WORDS], const uint64_t RC[ROUNDS][CAP_WORDS],
                                   int in_fd, int out_fd, uint64_t pt_len) {
    static constexpr size_t CHUNK = 1 << 20; // 1 MiB
    std::vector<uint8_t> inbuf(CHUNK + RATE_BYTES);
    std::vector<uint8_t> outbuf(CHUNK + RATE_BYTES);

    size_t tail = 0;
    uint64_t consumed = 0;

    while (consumed < pt_len) {
        size_t want = (size_t)std::min<uint64_t>((uint64_t)CHUNK, pt_len - consumed);
        size_t got = 0;
        if (!read_some(in_fd, inbuf.data() + tail, want, got)) throw std::runtime_error("read error");
        if (got == 0) throw std::runtime_error("unexpected EOF");

        consumed += got;
        size_t total = tail + got;
        size_t full = total / RATE_BYTES;
        size_t proc_bytes = full * RATE_BYTES;

        // process each full block, output in outbuf
        for (size_t off = 0; off < proc_bytes; off += RATE_BYTES) {
            uint8_t ks[RATE_BYTES];
            output_transform_rate(ks, S);

            // C = P ^ KS
            for (size_t i = 0; i < RATE_BYTES; i++) {
                outbuf[off + i] = (uint8_t)(inbuf[off + i] ^ ks[i]);
            }

            // duplex absorb ciphertext: S[rate] ^= C
            // but S[rate] currently equals KS, so KS ^ C = P; still OK: state becomes P.
            xor_rate(S, outbuf.data() + off);
            S[15] ^= DS_CT;
            permute_p1024_v2(S, RC);

            secure_zero(ks, sizeof(ks));
        }

        if (proc_bytes) {
            if (!write_all(out_fd, outbuf.data(), proc_bytes)) throw std::runtime_error("write error");
        }

        tail = total - proc_bytes;
        if (tail) std::memmove(inbuf.data(), inbuf.data() + proc_bytes, tail);
    }

    // final partial (tail bytes) and pad
    if (tail) {
        uint8_t ks[RATE_BYTES];
        output_transform_rate(ks, S);
        std::vector<uint8_t> ctail(tail);
        for (size_t i = 0; i < tail; i++) ctail[i] = (uint8_t)(inbuf[i] ^ ks[i]);
        if (!write_all(out_fd, ctail.data(), tail)) throw std::runtime_error("write error");
        absorb_rate_partial_and_pad(S, ctail.data(), tail, RC);
        secure_zero(ks, sizeof(ks));
        secure_zero(ctail.data(), ctail.size());
    } else {
        // pad-only
        absorb_rate_partial_and_pad(S, nullptr, 0, RC);
    }
}

static void symfrog_decrypt_stream(uint64_t S[STATE_WORDS], const uint64_t RC[ROUNDS][CAP_WORDS],
                                   int in_fd, int out_fd, uint64_t ct_len) {
    static constexpr size_t CHUNK = 1 << 20; // 1 MiB
    std::vector<uint8_t> inbuf(CHUNK + RATE_BYTES);
    std::vector<uint8_t> outbuf(CHUNK + RATE_BYTES);

    size_t tail = 0;
    uint64_t consumed = 0;

    while (consumed < ct_len) {
        size_t want = (size_t)std::min<uint64_t>((uint64_t)CHUNK, ct_len - consumed);
        size_t got = 0;
        if (!read_some(in_fd, inbuf.data() + tail, want, got)) throw std::runtime_error("read error");
        if (got == 0) throw std::runtime_error("unexpected EOF");

        consumed += got;
        size_t total = tail + got;
        size_t full = total / RATE_BYTES;
        size_t proc_bytes = full * RATE_BYTES;

        for (size_t off = 0; off < proc_bytes; off += RATE_BYTES) {
            uint8_t ks[RATE_BYTES];
            output_transform_rate(ks, S);

            // P = C ^ KS
            for (size_t i = 0; i < RATE_BYTES; i++) {
                outbuf[off + i] = (uint8_t)(inbuf[off + i] ^ ks[i]);
            }

            // absorb ciphertext C
            xor_rate(S, inbuf.data() + off);
            S[15] ^= DS_CT;
            permute_p1024_v2(S, RC);
            secure_zero(ks, sizeof(ks));
        }

        if (proc_bytes) {
            if (!write_all(out_fd, outbuf.data(), proc_bytes)) throw std::runtime_error("write error");
        }

        tail = total - proc_bytes;
        if (tail) std::memmove(inbuf.data(), inbuf.data() + proc_bytes, tail);
    }

    // final partial
    if (tail) {
        uint8_t ks[RATE_BYTES];
        output_transform_rate(ks, S);
        std::vector<uint8_t> ptail(tail);
        for (size_t i = 0; i < tail; i++) ptail[i] = (uint8_t)(inbuf[i] ^ ks[i]);
        if (!write_all(out_fd, ptail.data(), tail)) throw std::runtime_error("write error");
        // absorb ciphertext tail for padding
        absorb_rate_partial_and_pad(S, inbuf.data(), tail, RC);
        secure_zero(ks, sizeof(ks));
        secure_zero(ptail.data(), ptail.size());
    } else {
        absorb_rate_partial_and_pad(S, nullptr, 0, RC);
    }
}

// -------------------- File API --------------------
static uint64_t get_file_size_or_die(const char* path, bool quiet) {
    (void)quiet;
    struct stat st;
    if (::stat(path, &st) != 0) throw std::runtime_error("stat failed");
    if (!S_ISREG(st.st_mode)) throw std::runtime_error("input is not a regular file");
    return (uint64_t)st.st_size;
}

static std::string path_dir_of(const char* path) {
    std::string p = path ? std::string(path) : std::string();
    const auto pos = p.find_last_of('/');
    if (pos == std::string::npos) return ".";
    if (pos == 0) return "/";
    return p.substr(0, pos);
}

static std::string path_base_of(const char* path) {
    std::string p = path ? std::string(path) : std::string();
    const auto pos = p.find_last_of('/');
    if (pos == std::string::npos) return p;
    return p.substr(pos + 1);
}

// Create a temp file in the SAME directory as out_path so rename() is atomic.
// Uses mkstemp() to avoid predictable filenames.
static int open_temp_for_output_same_dir(const char* out_path, std::string& tmp_path) {
    const std::string dir = path_dir_of(out_path);
    const std::string base = path_base_of(out_path);
    std::string tmpl = dir + "/.symfrog." + base + ".XXXXXX";
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');

    int fd = ::mkstemp(buf.data());
    if (fd < 0) {
        throw std::runtime_error("mkstemp failed");
    }
    tmp_path.assign(buf.data());

    // best-effort hardening
    int fdflags = ::fcntl(fd, F_GETFD);
    if (fdflags >= 0) (void)::fcntl(fd, F_SETFD, fdflags | FD_CLOEXEC);
    (void)::fchmod(fd, 0600);

    return fd;
}

static void atomic_rename_or_die(const char* tmp, const char* out) {
    if (::rename(tmp, out) != 0) {
        throw std::runtime_error("rename failed");
    }
    (void)fsync_dir_of_path(out); // best-effort
}

static void symfrog_encrypt_file(const char* in_path, const char* out_path,
                                const uint8_t* ad, size_t ad_len,
                                const char* pass_or_null,
                                const uint8_t* rawkey_or_null,
                                const uint8_t* nonce_override_or_null,
                                bool paranoid_kdf,
                                const uint64_t RC[ROUNDS][CAP_WORDS],
                                bool quiet)
{
    uint64_t pt_len = get_file_size_or_die(in_path, quiet);
    int in_fd = ::open(in_path, O_RDONLY | O_CLOEXEC);
    if (in_fd < 0) throw std::runtime_error("open input failed");

    std::string tmp;
    int out_fd = open_temp_for_output_same_dir(out_path, tmp);
    if (out_fd < 0) { ::close(in_fd); throw std::runtime_error("open output failed"); }


// Ensure temp file is cleaned up on any exception (so callers don't see missing output without explanation).
auto cleanup_fail = [&](bool unlink_tmp) {
    if (in_fd >= 0) (void)::close(in_fd);
    if (out_fd >= 0) (void)::close(out_fd);
    if (unlink_tmp && !tmp.empty()) (void)::unlink(tmp.c_str());
};

    try {

    // Prepare header
    Header h{};
    std::memcpy(h.magic, MAGIC, 8);
    h.version = VERSION;
    h.flags = 0;
    h.ct_len = pt_len;
    std::memset(h.reserved, 0, sizeof(h.reserved));

    uint8_t nonce[NONCE_BYTES];
    const bool lock_quiet = !paranoid_kdf;
    MlockGuard lock_nonce(nonce, sizeof(nonce), lock_quiet);
    if (nonce_override_or_null) std::memcpy(nonce, nonce_override_or_null, NONCE_BYTES);
    else random_bytes(nonce, NONCE_BYTES);
    std::memcpy(h.nonce, nonce, NONCE_BYTES);

    uint8_t key[KEY_BYTES];
    MlockGuard lock_key(key, sizeof(key), lock_quiet);
    if (pass_or_null) {
        h.flags |= FLAG_KEY_DERIVED;
        random_bytes(h.salt, SALT_BYTES);
        kdf_argon2id(key, pass_or_null, h.salt, paranoid_kdf);
    } else if (rawkey_or_null) {
        std::memset(h.salt, 0, SALT_BYTES);
        std::memcpy(key, rawkey_or_null, KEY_BYTES);
    } else {
        ::close(in_fd); ::close(out_fd);
        throw std::runtime_error("no key material provided");
    }

    // Compute header_tag (binds AAD)
    compute_header_tag_keyed(RC, key, nonce, h, ad, ad_len, h.header_tag, quiet);
// Write header first
    uint8_t hdr_bytes[HEADER_BYTES];
    header_serialize(hdr_bytes, h);
    if (!write_all(out_fd, hdr_bytes, HEADER_BYTES)) {
        ::close(in_fd); ::close(out_fd);
        throw std::runtime_error("write header failed");
    }

    // Init state and absorb AD
    alignas(64) uint64_t S[STATE_WORDS];
    MlockGuard lock_state(S, sizeof(S), lock_quiet);
    symfrog_init(S, key, nonce, RC);
    symfrog_absorb_ad_mem(S, ad, ad_len, RC);

    // Encrypt stream (writes ciphertext right after header)
    symfrog_encrypt_stream(S, RC, in_fd, out_fd, pt_len);

    // Final tag
    uint8_t tag[TAG_BYTES];
    finalize_tag(S, RC, tag);
    if (!write_all(out_fd, tag, TAG_BYTES)) {
        ::close(in_fd); ::close(out_fd);
        throw std::runtime_error("write tag failed");
    }

    
    // Sanity: for regular files, ensure we appended the tag (helps catch truncation bugs early)
    {
        off_t cur = ::lseek(out_fd, 0, SEEK_CUR);
        if (cur >= 0) {
            const uint64_t expected = (uint64_t)HEADER_BYTES + (uint64_t)pt_len + (uint64_t)TAG_BYTES;
            if ((uint64_t)cur != expected) {
                ::close(in_fd);
                ::close(out_fd);
                ::unlink(tmp.c_str());
                throw std::runtime_error("internal: output size mismatch (tag not appended?)");
            }
        }
    }

// Durability
    if (::fsync(out_fd) != 0) {
        const int e = errno;
        (void)::close(in_fd);
        (void)::close(out_fd);
        (void)::unlink(tmp.c_str());
        throw std::runtime_error(std::string("fsync(out) failed: ") + std::strerror(e));
    }
    if (::close(out_fd) != 0) {
        const int e = errno;
        (void)::close(in_fd);
        (void)::unlink(tmp.c_str());
        throw std::runtime_error(std::string("close(out) failed: ") + std::strerror(e));
    }
    if (::close(in_fd) != 0) {
        if (!quiet) std::fprintf(stderr, "warning: close(in) failed: %s\n", std::strerror(errno));
    }

    atomic_rename_or_die(tmp.c_str(), out_path);

    // Best-effort directory fsync already done in atomic_rename_or_die
    secure_zero(S, sizeof(S));
    secure_zero(hdr_bytes, sizeof(hdr_bytes));
    secure_zero(key, sizeof(key));
    secure_zero(nonce, sizeof(nonce));
    secure_zero(tag, sizeof(tag));

    } catch (...) {
        cleanup_fail(true);
        throw;
    }
}

static bool symfrog_decrypt_file(const char* in_path, const char* out_path,
                                 const uint8_t* ad, size_t ad_len,
                                 const char* pass_or_null,
                                 const uint8_t* rawkey_or_null,
                                 bool paranoid_kdf,
                                 const uint64_t RC[ROUNDS][CAP_WORDS],
                                 bool quiet) {
    int in_fd = ::open(in_path, O_RDONLY | O_CLOEXEC);
    if (in_fd < 0) throw std::runtime_error("open input failed");

    uint8_t hdr_bytes[HEADER_BYTES];
    if (!read_all(in_fd, hdr_bytes, HEADER_BYTES)) {
        ::close(in_fd); return false;

    }
    Header h{};
    if (!header_parse(h, hdr_bytes)) {
        ::close(in_fd); return false;

    }
    if (std::memcmp(h.magic, MAGIC, 8) != 0 || h.version != VERSION) {
        ::close(in_fd); return false;

    }

    // Derive/load key
    uint8_t key[KEY_BYTES];
    MlockGuard lock_key(key, sizeof(key), quiet);
    if (h.flags & FLAG_KEY_DERIVED) {
        if (!pass_or_null) { ::close(in_fd); throw std::runtime_error("file expects passphrase (Argon2id)"); }
        kdf_argon2id(key, pass_or_null, h.salt, paranoid_kdf);
    } else {
        if (!rawkey_or_null) { ::close(in_fd); throw std::runtime_error("file expects raw key"); }
        std::memcpy(key, rawkey_or_null, KEY_BYTES);
    }

    // Verify header_tag (keyed, binds AAD too)
    uint8_t expected_hdr_tag[TAG_BYTES];
    compute_header_tag_keyed(RC, key, h.nonce, h, ad, ad_len, expected_hdr_tag, quiet);
if (!ct_memeq(h.header_tag, expected_hdr_tag, TAG_BYTES)) {
        ::close(in_fd);
        if (!quiet) std::fprintf(stderr, "SymFrog: header authentication failed (wrong key/pass, wrong AAD, or tampered header)\n");
        secure_zero(key, sizeof(key));
        return false;
    }

    // Key is ready; proceed

    // Position in_fd at ciphertext start (already there)
    // Derive ciphertext length from the actual file size (robust and avoids trusting header ct_len blindly)
    struct stat st{};
    if (::fstat(in_fd, &st) != 0) { ::close(in_fd); throw std::runtime_error("fstat(in) failed"); }
    const uint64_t file_size = (uint64_t)st.st_size;

    // Layout: [header (HEADER_BYTES)][ciphertext (ct_len)][tag (TAG_BYTES)]
    if (file_size < (uint64_t)HEADER_BYTES + (uint64_t)TAG_BYTES) {
        if (!quiet) {
            std::fprintf(stderr,
                         "SymFrog: ciphertext truncated: file_size=%llu, need >= %llu (header+tag)\n",
                         (unsigned long long)file_size,
                         (unsigned long long)((uint64_t)HEADER_BYTES + (uint64_t)TAG_BYTES));
        }
        ::close(in_fd);
        return false;
    }

    uint64_t ct_len = file_size - (uint64_t)HEADER_BYTES - (uint64_t)TAG_BYTES;
    if (h.ct_len != ct_len) {
        if (!quiet) {
            std::fprintf(stderr,
                "SymFrog: warning: header ct_len=%llu but file-derived ct_len=%llu; using file-derived.\n",
                (unsigned long long)h.ct_len, (unsigned long long)ct_len);
        }
    }

    // Read tag from file end
    const off_t tag_off = (off_t)(file_size - (uint64_t)TAG_BYTES);
    if (::lseek(in_fd, tag_off, SEEK_SET) < 0) { ::close(in_fd); throw std::runtime_error("lseek tag failed"); }
    uint8_t file_tag[TAG_BYTES];
    if (!read_all(in_fd, file_tag, TAG_BYTES)) { ::close(in_fd); throw std::runtime_error("read tag failed"); }

    // Back to ciphertext start
    if (::lseek(in_fd, (off_t)HEADER_BYTES, SEEK_SET) < 0) { ::close(in_fd); throw std::runtime_error("lseek ct failed"); }
std::string tmp;
    int out_fd = open_temp_for_output_same_dir(out_path, tmp);
    if (out_fd < 0) { ::close(in_fd); throw std::runtime_error("open output failed"); }



    // Init state and absorb AD
    alignas(64) uint64_t S[STATE_WORDS];
    MlockGuard lock_state(S, sizeof(S), quiet);
    symfrog_init(S, key, h.nonce, RC);
    symfrog_absorb_ad_mem(S, ad, ad_len, RC);

    bool ok = true;
    try {
        symfrog_decrypt_stream(S, RC, in_fd, out_fd, ct_len);
    } catch (...) {
        ok = false;
    }

    // Compute expected tag
    uint8_t expected[TAG_BYTES];
    finalize_tag(S, RC, expected);

    if (!ok || !ct_memeq(file_tag, expected, TAG_BYTES)) {
        // fail: wipe tmp, close, unlink
        (void)::fsync(out_fd);
        ::close(out_fd);
        ::close(in_fd);
        ::unlink(tmp.c_str());
        secure_zero(S, sizeof(S));
        secure_zero(key, sizeof(key));
        secure_zero(expected, sizeof(expected));
        if (!quiet) std::fprintf(stderr, "SymFrog: authentication failed (wrong key/pass, wrong AAD, or tampered ciphertext/tag)\n");
        return false;
    }

    if (::fsync(out_fd) != 0) {
        const int e = errno;
        (void)::close(in_fd);
        (void)::close(out_fd);
        (void)::unlink(tmp.c_str());
        throw std::runtime_error(std::string("fsync(out) failed: ") + std::strerror(e));
    }
    if (::close(out_fd) != 0) {
        const int e = errno;
        (void)::close(in_fd);
        (void)::unlink(tmp.c_str());
        throw std::runtime_error(std::string("close(out) failed: ") + std::strerror(e));
    }
    if (::close(in_fd) != 0) {
        if (!quiet) std::fprintf(stderr, "warning: close(in) failed: %s\n", std::strerror(errno));
    }

    atomic_rename_or_die(tmp.c_str(), out_path);

    secure_zero(S, sizeof(S));
    secure_zero(key, sizeof(key));
    secure_zero(expected, sizeof(expected));
    secure_zero(file_tag, sizeof(file_tag));
    return true;
}

// -------------------- Hash mode (FrogHash-512) --------------------
static void file_sha256_hex(const char* path, std::string& out_hex) {
    out_hex.clear();
    int fd = ::open(path, O_RDONLY);
    if (fd < 0) throw std::runtime_error("open failed");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) { ::close(fd); throw std::runtime_error("EVP_MD_CTX_new"); }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx); ::close(fd); throw std::runtime_error("DigestInit");
    }

    static constexpr size_t BUFSZ = 1 << 20;
    std::vector<uint8_t> buf(BUFSZ);
    while (true) {
        size_t got = 0;
        if (!read_some(fd, buf.data(), BUFSZ, got)) { EVP_MD_CTX_free(ctx); ::close(fd); throw std::runtime_error("read"); }
        if (got == 0) break;
        if (EVP_DigestUpdate(ctx, buf.data(), got) != 1) { EVP_MD_CTX_free(ctx); ::close(fd); throw std::runtime_error("DigestUpdate"); }
    }

    uint8_t md[32];
    unsigned int mdlen = 0;
    if (EVP_DigestFinal_ex(ctx, md, &mdlen) != 1 || mdlen != 32) {
        EVP_MD_CTX_free(ctx); ::close(fd); throw std::runtime_error("DigestFinal");
    }

    out_hex = bytes_to_hex(md, 32);
    secure_zero(md, sizeof(md));
    EVP_MD_CTX_free(ctx);
    ::close(fd);
}

static void froghash512_file(const uint64_t RC[ROUNDS][CAP_WORDS], const char* in_path, uint8_t out[64]) {
    int fd = ::open(in_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) throw std::runtime_error("open input failed");

    alignas(64) uint64_t S[STATE_WORDS];
    for (size_t i = 0; i < STATE_WORDS; i++) S[i] = 0;
    S[0] ^= 0x46524F4748415348ULL; // FROGHASH
    S[1] ^= 0x3531322D56322D20ULL; // 512-V2-
    permute_p1024_v2(S, RC);

    static constexpr size_t CHUNK = 1 << 20;
    std::vector<uint8_t> buf(CHUNK + RATE_BYTES);
    size_t tail = 0;

    while (true) {
        size_t got = 0;
        if (!read_some(fd, buf.data() + tail, CHUNK, got)) { ::close(fd); throw std::runtime_error("read"); }
        if (got == 0) break;

        size_t total = tail + got;
        size_t full = total / RATE_BYTES;
        size_t proc = full * RATE_BYTES;

        for (size_t off = 0; off < proc; off += RATE_BYTES) {
            xor_rate(S, buf.data() + off);
            permute_p1024_v2(S, RC);
        }

        tail = total - proc;
        if (tail) std::memmove(buf.data(), buf.data() + proc, tail);
    }

    // pad final
    for (size_t i = 0; i < tail; i++) xor_byte_rate(S, i, buf[i]);
    xor_byte_rate(S, tail, 0x80);
    xor_byte_rate(S, RATE_BYTES - 1, 0x01);
    permute_p1024_v2(S, RC);

    uint8_t rate[RATE_BYTES];
    output_transform_rate(rate, S);
    std::memcpy(out, rate, 64);

    secure_zero(rate, sizeof(rate));
    secure_zero(S, sizeof(S));
    ::close(fd);
}

// -------------------- CLI --------------------
static void print_help() {
    std::puts(
"SymFrog-512 (FROGSPONGE-1024 v2) - paranoid AEAD + FrogHash-512\n"
"\n"
"Usage:\n"
"  symfrog512 --help\n"
"  symfrog512 --test-all\n"
"  symfrog512 --benchmark\n"
"\n"
"Encrypt (AEAD):\n"
"  symfrog512 enc <in> <out> [--pass <pw> | --key-hex <hex1024>] [--ad <hex>] [--nonce-hex <hex256>] [--paranoid] [--quiet|-q]\n"
"\n"
"Decrypt (AEAD):\n"
"  symfrog512 dec <in> <out> [--pass <pw> | --key-hex <hex1024>] [--ad <hex>] [--paranoid] [--quiet|-q]\n"
"\n"
"Hash (FrogHash-512):\n"
"  symfrog512 hash <in> [--out <file>] [--quiet|-q]\n"
"\n"
"Notes:\n"
"  --paranoid uses Argon2id SENSITIVE limits (slow, huge memory). Default is MODERATE.\n"
"  --quiet (or -q) suppresses non-error output.\n"
"  --ad is Additional Authenticated Data in hex (binds header + ciphertext).\n"
"  --nonce-hex is optional; if omitted, a random 256-bit nonce is generated.\n"
"\n"
"Examples:\n"
"  symfrog512 enc secret.txt secret.syf --pass 'mypw' --ad 486561646572\n"
"  symfrog512 dec secret.syf secret.txt --pass 'mypw' --ad 486561646572\n"
"  symfrog512 hash secret.txt\n"
    );
}

static bool parse_opt_value(int& i, int argc, char** argv, const char* opt, const char*& out) {
    if (std::strcmp(argv[i], opt) != 0) return false;
    if (i + 1 >= argc) throw std::runtime_error("missing option value");
    out = argv[i+1];
    i += 2;
    return true;
}

static bool parse_flag(int& i, int /*argc*/, char** argv, const char* flag) {
    if (std::strcmp(argv[i], flag) != 0) return false;
    i += 1;
    return true;
}

// -------------------- Tests --------------------
static void write_random_file(const char* path, size_t nbytes) {
    const int fd = ::open(path, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0600);
    if (fd < 0) die_errno("open(random-file)");

    std::vector<uint8_t> buf(64 * 1024);
    size_t remaining = nbytes;

    while (remaining) {
        const size_t want = std::min(remaining, buf.size());
        randombytes_buf(buf.data(), want);
        // CORREÇÃO AQUI: remover a barra invertida antes das aspas
        if (!write_all(fd, buf.data(), want)) die_errno("write(random-file)");
        remaining -= want;
    }

    if (::fsync(fd) < 0) die_errno("fsync(random-file)");
    if (::close(fd) < 0) die_errno("close(random-file)");
}

static void flip_one_byte(const char* path, off_t off) {
    int fd = ::open(path, O_RDWR);
    if (fd < 0) throw std::runtime_error("open for flip failed");
    if (::lseek(fd, off, SEEK_SET) < 0) { ::close(fd); throw std::runtime_error("lseek flip failed"); }
    uint8_t b;
    if (!read_all(fd, &b, 1)) { ::close(fd); throw std::runtime_error("read flip failed"); }
    b ^= 0x01;
    if (::lseek(fd, off, SEEK_SET) < 0) { ::close(fd); throw std::runtime_error("lseek flip failed"); }
    if (!write_all(fd, &b, 1)) { ::close(fd); throw std::runtime_error("write flip failed"); }
    (void)::fsync(fd);
    ::close(fd);
}

[[maybe_unused]] static std::string mktemp_dir() {
    char tmpl[] = "/tmp/symfrog_test_XXXXXX";
    char* d = ::mkdtemp(tmpl);
    if (!d) throw std::runtime_error("mkdtemp failed");
    return std::string(d);
}

// Create (or reuse) a directory in the current working directory.
// Used by --test-all when we want to keep artifacts for debugging.
static std::string ensure_local_test_dir(const char* name) {
    if (!name || !*name) name = "symfrog_test_out";
    if (::mkdir(name, 0700) != 0) {
        if (errno != EEXIST) throw std::runtime_error("mkdir test dir failed");
    }
    return std::string(name);
}

[[maybe_unused]] static void rm_rf_dir(const std::string& d) {
    DIR* dir = ::opendir(d.c_str());
    if (!dir) return;
    struct dirent* ent;
    while ((ent = ::readdir(dir)) != nullptr) {
        if (!std::strcmp(ent->d_name, ".") || !std::strcmp(ent->d_name, "..")) continue;
        std::string p = d + "/" + ent->d_name;
        ::unlink(p.c_str());
    }
    ::closedir(dir);
    ::rmdir(d.c_str());
}

static bool run_self_tests(const uint64_t RC[ROUNDS][CAP_WORDS], bool quiet) {
    std::puts("SymFrog --test-all: starting (this may take a bit) ...");

    // Keep artifacts for inspection in the current directory.
    // (The previous /tmp auto-delete behavior made debugging failures painful.)
    std::string d = ensure_local_test_dir("symfrog_test_out");
    std::fprintf(stderr, "SymFrog --test-all: writing artifacts to ./%s\n", d.c_str());
    bool all_ok = true;

    auto path = [&](const char* name) {
        return d + "/" + name;
    };

    // Test vectors: file sizes
    std::vector<size_t> sizes = {0,1,2,7,8,15,16,63,64,65,127,128,129,4096,65536,65536+13,1<<20, (1<<20)+7};

    // Fixed AD
    std::vector<uint8_t> ad = {'H','E','A','D','E','R'};
    std::string ad_hex = bytes_to_hex(ad.data(), ad.size());

    // Password and raw key
    const char* pw = "correct horse battery staple (symfrog)";
    uint8_t rawkey[KEY_BYTES];
    randombytes_buf(rawkey, sizeof(rawkey));

    // Nonce fixed for determinism in tests
    uint8_t nonce[NONCE_BYTES];
    for (size_t i = 0; i < NONCE_BYTES; i++) nonce[i] = (uint8_t)i;

    for (size_t n : sizes) {
        try {
            // Unique per-size filenames so we can inspect failures.
            char in_name[64], enc_name[64], dec_name[64];
            std::snprintf(in_name,  sizeof(in_name),  "in_%zu.bin",  n);
            std::snprintf(enc_name, sizeof(enc_name), "enc_%zu.syf", n);
            std::snprintf(dec_name, sizeof(dec_name), "dec_%zu.bin", n);

            std::string in  = path(in_name);
            std::string enc = path(enc_name);
            std::string dec = path(dec_name);

            write_random_file(in.c_str(), n);

            // Encrypt with pass (MODERATE) but deterministic nonce override
            symfrog_encrypt_file(in.c_str(), enc.c_str(),
                                 ad.data(), ad.size(),
                                 pw, nullptr, nonce,
                                 /*paranoid_kdf=*/false,
                                 RC, quiet);// Decrypt back
            bool ok = symfrog_decrypt_file(enc.c_str(), dec.c_str(),
                                           ad.data(), ad.size(),
                                           pw, nullptr,
                                           /*paranoid_kdf=*/false,
                                           RC,
                                           /*quiet=*/true);
            if (!ok) {
                std::fprintf(stderr, "FAIL: decrypt (pass) size=%zu\n", n);
                all_ok = false;
                continue;
            }

            // Compare hashes
            std::string h1, h2;
            file_sha256_hex(in.c_str(), h1);
            file_sha256_hex(dec.c_str(), h2);
            if (h1 != h2) {
                std::fprintf(stderr, "FAIL: content mismatch (pass) size=%zu\n", n);
                all_ok = false;
            }

            // Tamper tests (ciphertext / tag / header)
            // 1) Flip a byte inside ciphertext (if any)
            if (n > 0) {
                std::string t = path("tamper_ct.syf");
                // copy enc -> t
                {
                    int sfd = ::open(enc.c_str(), O_RDONLY);
                    int dfd = ::open(t.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0600);
                    if (sfd < 0 || dfd < 0) throw std::runtime_error("copy fail");
                    std::vector<uint8_t> buf(1<<20);
                    while (true) {
                        size_t got = 0;
                        if (!read_some(sfd, buf.data(), buf.size(), got)) throw std::runtime_error("copy read");
                        if (got == 0) break;
                        if (!write_all(dfd, buf.data(), got)) throw std::runtime_error("copy write");
                    }
                    (void)::fsync(dfd);
                    ::close(sfd); ::close(dfd);
                }
                flip_one_byte(t.c_str(), (off_t)HEADER_BYTES); // first byte of ciphertext
                std::string out_tamper_ct = path("tamper_out.bin");
                bool ok2 = symfrog_decrypt_file(t.c_str(), out_tamper_ct.c_str(),
                                                ad.data(), ad.size(),
                                                pw, nullptr,
                                                false, RC, true);
                if (ok2) {
                    std::fprintf(stderr, "FAIL: tampered ciphertext decrypted (pass) size=%zu\n", n);
                    all_ok = false;
                }
                ::unlink(out_tamper_ct.c_str());
                ::unlink(t.c_str());
            }

            // 2) Flip tag byte
            {
                std::string t = path("tamper_tag.syf");
                // copy enc -> t
                int sfd = ::open(enc.c_str(), O_RDONLY);
                int dfd = ::open(t.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0600);
                if (sfd < 0 || dfd < 0) throw std::runtime_error("copy fail");
                std::vector<uint8_t> buf(1<<20);
                while (true) {
                    size_t got = 0;
                    if (!read_some(sfd, buf.data(), buf.size(), got)) throw std::runtime_error("copy read");
                    if (got == 0) break;
                    if (!write_all(dfd, buf.data(), got)) throw std::runtime_error("copy write");
                }
                (void)::fsync(dfd);
                ::close(sfd); ::close(dfd);

                // flip last byte of file (tag region)
                off_t sz = (off_t)(HEADER_BYTES + n + TAG_BYTES);
                flip_one_byte(t.c_str(), sz - 1);

                std::string out_tamper_tag = path("tamper_out2.bin");
                bool ok3 = symfrog_decrypt_file(t.c_str(), out_tamper_tag.c_str(),
                                                ad.data(), ad.size(),
                                                pw, nullptr,
                                                false, RC, true);
                if (ok3) {
                    std::fprintf(stderr, "FAIL: tampered tag decrypted (pass) size=%zu\n", n);
                    all_ok = false;
                }
                ::unlink(out_tamper_tag.c_str());
                ::unlink(t.c_str());
            }

            // 3) Wrong AAD should fail
            {
                std::vector<uint8_t> bad_ad = {'B','A','D'};
                std::string out_bad_ad = path("bad_ad.bin");
                bool ok4 = symfrog_decrypt_file(enc.c_str(), out_bad_ad.c_str(),
                                                bad_ad.data(), bad_ad.size(),
                                                pw, nullptr,
                                                false, RC, true);
                if (ok4) {
                    std::fprintf(stderr, "FAIL: wrong AAD decrypted (pass) size=%zu\n", n);
                    all_ok = false;
                }
                ::unlink(out_bad_ad.c_str());
            }

            // 3b) Wrong password should fail
            {
                const char* bad_pw = "totally wrong password";
                std::string out_bad_pw = path("bad_pw.bin");
                bool okpw = symfrog_decrypt_file(enc.c_str(), out_bad_pw.c_str(),
                                                 ad.data(), ad.size(),
                                                 bad_pw, nullptr,
                                                 false, RC, true);
                if (okpw) {
                    std::fprintf(stderr, "FAIL: wrong password decrypted (pass) size=%zu\n", n);
                    all_ok = false;
                }
                ::unlink(out_bad_pw.c_str());
            }

            // 3c) Header tamper should fail (keyed header_tag)
            {
                std::string t = path("tamper_hdr.syf");
                // copy enc -> t
                int sfd = ::open(enc.c_str(), O_RDONLY);
                int dfd = ::open(t.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0600);
                if (sfd < 0 || dfd < 0) throw std::runtime_error("copy fail");
                std::vector<uint8_t> buf(1<<20);
                while (true) {
                    size_t got = 0;
                    if (!read_some(sfd, buf.data(), buf.size(), got)) throw std::runtime_error("copy read");
                    if (got == 0) break;
                    if (!write_all(dfd, buf.data(), got)) throw std::runtime_error("copy write");
                }
                (void)::fsync(dfd);
                ::close(sfd); ::close(dfd);

                // Flip a byte in salt region (after magic/version/flags/ct_len/nonce)
                flip_one_byte(t.c_str(), 4 + 4 + 8 + NONCE_BYTES + 3); // inside salt

                std::string out_tamper_hdr = path("tamper_hdr_out.bin");
                bool okh = symfrog_decrypt_file(t.c_str(), out_tamper_hdr.c_str(),
                                                ad.data(), ad.size(),
                                                pw, nullptr,
                                                false, RC, true);
                if (okh) {
                    std::fprintf(stderr, "FAIL: tampered header decrypted (pass) size=%zu\n", n);
                    all_ok = false;
                }
                ::unlink(out_tamper_hdr.c_str());
                ::unlink(t.c_str());
            }

            // 3d) Truncation should fail
            {
                std::string t = path("trunc.syf");
                int sfd = ::open(enc.c_str(), O_RDONLY);
                int dfd = ::open(t.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0600);
                if (sfd < 0 || dfd < 0) throw std::runtime_error("copy fail");
                std::vector<uint8_t> buf(1<<20);
                size_t total = 0;
                while (true) {
                    size_t got = 0;
                    if (!read_some(sfd, buf.data(), buf.size(), got)) throw std::runtime_error("copy read");
                    if (got == 0) break;
                    total += got;
                    if (!write_all(dfd, buf.data(), got)) throw std::runtime_error("copy write");
                }
                (void)::fsync(dfd);
                ::close(sfd); ::close(dfd);

                // Truncate last 7 bytes (if possible)
                if (total > 7) {
                    int tfd = ::open(t.c_str(), O_WRONLY);
                    if (tfd < 0) throw std::runtime_error("open trunc fail");
                    if (::ftruncate(tfd, (off_t)(total - 7)) != 0) throw std::runtime_error("ftruncate fail");
                    (void)::fsync(tfd);
                    ::close(tfd);
                }

                std::string out_trunc = path("trunc_out.bin");
                bool okt = symfrog_decrypt_file(t.c_str(), out_trunc.c_str(),
                                                ad.data(), ad.size(),
                                                pw, nullptr,
                                                false, RC, true);
                if (okt) {
                    std::fprintf(stderr, "FAIL: truncated file decrypted (pass) size=%zu\n", n);
                    all_ok = false;
                }
                ::unlink(out_trunc.c_str());
                ::unlink(t.c_str());
            }
            // 4) Raw-key mode roundtrip
            {
                std::string enc2 = path("out2.syf");
                std::string dec2 = path("out2.bin");
                symfrog_encrypt_file(in.c_str(), enc2.c_str(),
                                     ad.data(), ad.size(),
                                     nullptr, rawkey, nonce,
                                     false, RC, quiet);
                bool ok5 = symfrog_decrypt_file(enc2.c_str(), dec2.c_str(),
                                                ad.data(), ad.size(),
                                                nullptr, rawkey,
                                                false, RC, true);
                if (!ok5) {
                    std::fprintf(stderr, "FAIL: decrypt (rawkey) size=%zu\n", n);
                    all_ok = false;
                } else {
                    std::string h3, h4;
                    file_sha256_hex(in.c_str(), h3);
                    file_sha256_hex(dec2.c_str(), h4);
                    if (h3 != h4) {
                        std::fprintf(stderr, "FAIL: content mismatch (rawkey) size=%zu\n", n);
                        all_ok = false;
                    }
                }

                // Wrong key should fail
                uint8_t wrong[KEY_BYTES];
                randombytes_buf(wrong, sizeof(wrong));
                std::string out_wrong_key = path("wrong_key.bin");
                bool ok6 = symfrog_decrypt_file(enc2.c_str(), out_wrong_key.c_str(),
                                                ad.data(), ad.size(),
                                                nullptr, wrong,
                                                false, RC, true);
                if (ok6) {
                    std::fprintf(stderr, "FAIL: wrong key decrypted (rawkey) size=%zu\n", n);
                    all_ok = false;
                }
                ::unlink(out_wrong_key.c_str());
                ::unlink(enc2.c_str());
                ::unlink(dec2.c_str());
            }

            // NOTE: We intentionally keep in/enc/dec on disk for debugging.

        } catch (const std::exception& e) {
            std::fprintf(stderr, "FAIL: exception in tests size=%zu: %s\n", n, e.what());
            all_ok = false;
        }
    }

    // Intentionally do NOT delete the directory; user asked to keep artifacts.

    if (all_ok) std::puts("SymFrog --test-all: ALL TESTS PASSED ✅");
    else std::puts("SymFrog --test-all: FAILURES DETECTED ❌");
    return all_ok;
}

// -------------------- Benchmarking --------------------
static inline uint64_t now_ns() {
    struct timespec ts;
    ::clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void run_benchmarks(const uint64_t RC[ROUNDS][CAP_WORDS]) {
    std::puts("SymFrog --benchmark: starting...");

    // 1) Permutation micro-bench
    {
        alignas(64) uint64_t S[STATE_WORDS];
        for (size_t i = 0; i < STATE_WORDS; i++) S[i] = (uint64_t)randombytes_random() << 32 ^ randombytes_random();

        const uint64_t iters = 200000;
        uint64_t t0 = now_ns();
        for (uint64_t i = 0; i < iters; i++) {
            permute_p1024_v2(S, RC);
        }
        uint64_t t1 = now_ns();
        double dt = (double)(t1 - t0) / 1e9;
        double per = (double)(t1 - t0) / (double)iters;
        std::printf("  P1024-v2: iters=%llu time=%.3fs  %.1f ns/perm\n",
                    (unsigned long long)iters, dt, per);
        secure_zero(S, sizeof(S));
    }

    // 2) Streaming AEAD core bench (in-memory)
    {
        const size_t bytes = 64ull * 1024ull * 1024ull; // 64 MiB
        std::vector<uint8_t> buf(bytes);
        randombytes_buf(buf.data(), buf.size());

        uint8_t key[KEY_BYTES];
        uint8_t nonce[NONCE_BYTES];
        random_bytes(key, KEY_BYTES);
        random_bytes(nonce, NONCE_BYTES);

        alignas(64) uint64_t S[STATE_WORDS];
        symfrog_init(S, key, nonce, RC);

        // empty AD domain sep
        symfrog_absorb_ad_mem(S, nullptr, 0, RC);

        uint64_t t0 = now_ns();
        // encrypt in place-ish: create ctmp for absorption but keep ct in buf
        for (size_t off = 0; off + RATE_BYTES <= buf.size(); off += RATE_BYTES) {
            uint8_t ks[RATE_BYTES];
            output_transform_rate(ks, S);
            for (size_t i = 0; i < RATE_BYTES; i++) buf[off+i] ^= ks[i]; // now buf is ciphertext
            xor_rate(S, buf.data() + off);
            S[15] ^= DS_CT;
            permute_p1024_v2(S, RC);
            secure_zero(ks, sizeof(ks));
        }
        // final pad-only (buffer is exact multiple here)
        absorb_rate_partial_and_pad(S, nullptr, 0, RC);
        uint8_t tag[TAG_BYTES];
        finalize_tag(S, RC, tag);
        uint64_t t1 = now_ns();
        double dt = (double)(t1 - t0) / 1e9;
        double mbps = (double)bytes / (1024.0*1024.0) / dt;
        std::printf("  AEAD core encrypt (no I/O, no KDF): %.1f MiB/s (%.3fs for %zu MiB)\n",
                    mbps, dt, bytes/(1024*1024));

        secure_zero(S, sizeof(S));
        secure_zero(key, sizeof(key));
        secure_zero(nonce, sizeof(nonce));
        secure_zero(tag, sizeof(tag));
        secure_zero(buf.data(), buf.size());
    }

    std::puts("SymFrog --benchmark: done.");
}

// -------------------- Main --------------------
int main(int argc, char** argv) {
    if (argc < 2) {
        print_help();
        return 1;
    }

    if (sodium_init() < 0) {
        die_msg("libsodium init failed");
        return 2;
    }

    uint64_t RC[ROUNDS][CAP_WORDS];
    gen_round_constants(RC);

    bool quiet = false;

    // Global flags (anywhere)
    for (int i = 1; i < argc; ) {
        if (std::strcmp(argv[i], "--help") == 0 || std::strcmp(argv[i], "-h") == 0) {
            print_help();
            return 0;
        }
        if (std::strcmp(argv[i], "--test-all") == 0) {
            bool ok = run_self_tests(RC, quiet);
            return ok ? 0 : 3;
        }
        if (std::strcmp(argv[i], "--quiet") == 0 || std::strcmp(argv[i], "-q") == 0) { quiet = true; }
        if (std::strcmp(argv[i], "--benchmark") == 0 || std::strcmp(argv[i], "--benchmarking") == 0) {
            run_benchmarks(RC);
            return 0;
        }
        i++;
    }

    const char* cmd = argv[1];

    try {
        if (std::strcmp(cmd, "enc") == 0) {
            if (argc < 4) throw std::runtime_error("enc requires <in> <out>");
            const char* in  = argv[2];
            const char* out = argv[3];

            const char* pass = nullptr;
            const char* key_hex = nullptr;
            const char* ad_hex = nullptr;
            const char* nonce_hex = nullptr;
            bool paranoid = false;

            for (int i = 4; i < argc; ) {
                if (parse_flag(i, argc, argv, "--quiet") || parse_flag(i, argc, argv, "-q")) { quiet = true; continue; }
                if (parse_flag(i, argc, argv, "--paranoid")) { paranoid = true; continue; }
                if (parse_opt_value(i, argc, argv, "--pass", pass)) continue;
                if (parse_opt_value(i, argc, argv, "--key-hex", key_hex)) continue;
                if (parse_opt_value(i, argc, argv, "--ad", ad_hex)) continue;
                if (parse_opt_value(i, argc, argv, "--nonce-hex", nonce_hex)) continue;
                throw std::runtime_error("unknown option for enc");
            }

            std::vector<uint8_t> ad;
            if (ad_hex) {
                if (!hex_to_bytes(ad_hex, ad)) throw std::runtime_error("bad --ad hex");
            }

            uint8_t nonce_override[NONCE_BYTES];
            uint8_t* nonce_ptr = nullptr;
            if (nonce_hex) {
                std::vector<uint8_t> nb;
                if (!hex_to_bytes(nonce_hex, nb) || nb.size() != NONCE_BYTES) throw std::runtime_error("bad --nonce-hex (need 64 hex chars)");
                std::memcpy(nonce_override, nb.data(), NONCE_BYTES);
                nonce_ptr = nonce_override;
                secure_zero(nb.data(), nb.size());
            }

            uint8_t rawkey[KEY_BYTES];
            uint8_t* rawkey_ptr = nullptr;
            if (key_hex) {
                std::vector<uint8_t> kb;
                if (!hex_to_bytes(key_hex, kb) || kb.size() != KEY_BYTES) throw std::runtime_error("bad --key-hex (need 256 hex bytes / 2048 hex chars)");
                std::memcpy(rawkey, kb.data(), KEY_BYTES);
                rawkey_ptr = rawkey;
                secure_zero(kb.data(), kb.size());
            }

            if (!!pass == !!rawkey_ptr) throw std::runtime_error("provide exactly one of --pass or --key-hex");

            symfrog_encrypt_file(in, out,
                                 ad.empty() ? nullptr : ad.data(), ad.size(),
                                 pass, rawkey_ptr, nonce_ptr,
                                 paranoid,
                                 RC, quiet);
            std::puts("OK: encrypted");
            secure_zero(rawkey, sizeof(rawkey));
            secure_zero(nonce_override, sizeof(nonce_override));
            return 0;
        }
        else if (std::strcmp(cmd, "dec") == 0) {
            if (argc < 4) throw std::runtime_error("dec requires <in> <out>");
            const char* in  = argv[2];
            const char* out = argv[3];

            const char* pass = nullptr;
            const char* key_hex = nullptr;
            const char* ad_hex = nullptr;
            bool paranoid = false;

            for (int i = 4; i < argc; ) {
                if (parse_flag(i, argc, argv, "--quiet") || parse_flag(i, argc, argv, "-q")) { quiet = true; continue; }
                if (parse_flag(i, argc, argv, "--paranoid")) { paranoid = true; continue; }
                if (parse_opt_value(i, argc, argv, "--pass", pass)) continue;
                if (parse_opt_value(i, argc, argv, "--key-hex", key_hex)) continue;
                if (parse_opt_value(i, argc, argv, "--ad", ad_hex)) continue;
                throw std::runtime_error("unknown option for dec");
            }

            std::vector<uint8_t> ad;
            if (ad_hex) {
                if (!hex_to_bytes(ad_hex, ad)) throw std::runtime_error("bad --ad hex");
            }

            uint8_t rawkey[KEY_BYTES];
            uint8_t* rawkey_ptr = nullptr;
            if (key_hex) {
                std::vector<uint8_t> kb;
                if (!hex_to_bytes(key_hex, kb) || kb.size() != KEY_BYTES) throw std::runtime_error("bad --key-hex");
                std::memcpy(rawkey, kb.data(), KEY_BYTES);
                rawkey_ptr = rawkey;
                secure_zero(kb.data(), kb.size());
            }

            if (!!pass == !!rawkey_ptr) throw std::runtime_error("provide exactly one of --pass or --key-hex");

            bool ok = symfrog_decrypt_file(in, out,
                                           ad.empty() ? nullptr : ad.data(), ad.size(),
                                           pass, rawkey_ptr,
                                           paranoid,
                                           RC,
                                           quiet);
            secure_zero(rawkey, sizeof(rawkey));
            if (!ok) return 5;
            std::puts("OK: decrypted");
            return 0;
        }
        else if (std::strcmp(cmd, "hash") == 0) {
            if (argc < 3) throw std::runtime_error("hash requires <in>");
            const char* in = argv[2];
            const char* out_path = nullptr;

            for (int i = 3; i < argc; ) {
                if (parse_flag(i, argc, argv, "--quiet") || parse_flag(i, argc, argv, "-q")) { quiet = true; continue; }
                if (parse_opt_value(i, argc, argv, "--out", out_path)) continue;
                throw std::runtime_error("unknown option for hash");
            }

            uint8_t digest[64];
            froghash512_file(RC, in, digest);

            std::string hex = bytes_to_hex(digest, 64);
            if (out_path) {
                int fd = ::open(out_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
                if (fd < 0) throw std::runtime_error("open --out failed");
                if (!write_all(fd, (const uint8_t*)hex.c_str(), hex.size())) { ::close(fd); throw std::runtime_error("write out failed"); }
                if (!write_all(fd, (const uint8_t*)"\n", 1)) { ::close(fd); throw std::runtime_error("write out failed"); }
                if (::fsync(fd) != 0) {
                    const int e = errno;
                    (void)::close(fd);
                    throw std::runtime_error(std::string("fsync(out) failed: ") + std::strerror(e));
                }
                if (::close(fd) != 0) {
                    const int e = errno;
                    throw std::runtime_error(std::string("close(out) failed: ") + std::strerror(e));
                }
                if (!quiet) std::puts("OK: hash written");
            } else {
                std::printf("%s\n", hex.c_str());
            }
            secure_zero(digest, sizeof(digest));
            return 0;
        }
        else {
            throw std::runtime_error("unknown command");
        }
    } catch (const std::exception& e) {
        die_msg(e.what());
        return 2;
    }
}
