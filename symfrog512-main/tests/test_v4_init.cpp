// Independent check of the byte representation of the v4 HKDF initial state.
#define main symfrog_application_main
#include "../src/symfrog512.cpp"
#undef main
#include <array>
#include <cstdio>
#include <random>
#include <bit>
int main() {
    if (sodium_init() < 0) return 2;
    std::array<uint8_t, KEY_BYTES> key{};
    std::array<uint8_t, NONCE_BYTES> nonce{};
    for (size_t i = 0; i < key.size(); ++i) key[i] = static_cast<uint8_t>(i);
    for (size_t i = 0; i < nonce.size(); ++i) nonce[i] = static_cast<uint8_t>(i);
    uint64_t S[STATE_WORDS]{};
    init_state_with_key_nonce(S, key.data(), nonce.data(), VERSION_HKDF);
    uint8_t buf[STATE_BYTES];
    for (size_t i=0; i<STATE_WORDS; ++i) store64_le(buf + i * 8, S[i]);
    for (uint8_t b:buf) std::printf("%02x",static_cast<unsigned>(b));
    std::putchar('\n');
    // Stress the formerly exact XOR-cancellation identity over 2,048
    // randomized pairs; this is a regression/property test, NOT a proof.
    std::mt19937_64 rng(0x20261018U);
    for (size_t test = 0; test < 2048; ++test) {
        std::array<uint8_t, KEY_BYTES> related{};
        std::array<uint8_t, NONCE_BYTES> adjusted{};
        for (size_t i=0; i<key.size(); ++i) key[i] = static_cast<uint8_t>(rng());
        for (size_t i=0; i<nonce.size(); ++i) nonce[i] = static_cast<uint8_t>(rng());
        related = key;
        adjusted = nonce;
        for (size_t i=0; i<NONCE_BYTES; ++i) {
            const uint8_t delta=static_cast<uint8_t>(rng());
            related[96+i] ^= delta;
            adjusted[i] ^= delta;
        }
        uint64_t a[STATE_WORDS]{}, b[STATE_WORDS]{};
        init_state_with_key_nonce(a,key.data(),nonce.data(),VERSION_HKDF);
        init_state_with_key_nonce(b,related.data(),adjusted.data(),VERSION_HKDF);
        if (std::equal(std::begin(a),std::end(a),std::begin(b))) return 3;
        secure_zero(a,sizeof(a));secure_zero(b,sizeof(b));
    }
    secure_zero(S,sizeof(S));secure_zero(buf,sizeof(buf));
    return 0;
}
