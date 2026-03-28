
#include <array>
#include <bitset>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <numeric>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <string_view>
#include <tuple>
#include <vector>

#define main symfrog_original_main
#include "symfrog512.cpp"
#undef main

namespace fs = std::filesystem;

static std::mt19937_64 lab_rng(0x5341504F475054ULL);

struct CsvWriter {
    std::ofstream out;
    explicit CsvWriter(const fs::path& p) : out(p) {}
    template<typename... Ts>
    void row(const Ts&... xs) {
        bool first = true;
        ((out << (first ? "" : ",") << xs, first = false), ...);
        out << "\n";
    }
};

static fs::path lab_results_dir = "symfrog_full_suite_results";

static uint64_t lab_rand_u64() { return lab_rng(); }

static std::array<uint64_t, STATE_WORDS> lab_random_state() {
    std::array<uint64_t, STATE_WORDS> s{};
    for (auto &x : s) x = lab_rand_u64();
    return s;
}

static std::array<uint64_t, STATE_WORDS> lab_zero_state() {
    std::array<uint64_t, STATE_WORDS> s{};
    s.fill(0);
    return s;
}

static std::array<uint64_t, STATE_WORDS> lab_complement_state(const std::array<uint64_t, STATE_WORDS>& s) {
    std::array<uint64_t, STATE_WORDS> t{};
    for (size_t i = 0; i < STATE_WORDS; ++i) t[i] = ~s[i];
    return t;
}

static std::array<uint64_t, STATE_WORDS> lab_rotate_words_state(const std::array<uint64_t, STATE_WORDS>& s, int r) {
    std::array<uint64_t, STATE_WORDS> t{};
    for (size_t i = 0; i < STATE_WORDS; ++i) t[(i + r) & 15] = s[i];
    return t;
}

static void lab_permute(std::array<uint64_t, STATE_WORDS>& s, const uint64_t RC[ROUNDS][CAP_WORDS], int rounds = ROUNDS) {
    for (int r = 0; r < rounds; ++r) {
        for (size_t j = 0; j < CAP_WORDS; ++j) s[RATE_WORDS + j] ^= RC[r][j];
        mixer_layer(s.data());
        chi_layer(s.data());
        kick_layer(s.data());
        rotate_shuffle(s.data());
    }
}

static int lab_hamming_u64(uint64_t a) { return (int)__builtin_popcountll(a); }

static int lab_hamming_state(const std::array<uint64_t, STATE_WORDS>& a, const std::array<uint64_t, STATE_WORDS>& b) {
    int d = 0;
    for (size_t i = 0; i < STATE_WORDS; ++i) d += lab_hamming_u64(a[i] ^ b[i]);
    return d;
}

static int lab_weight_state(const std::array<uint64_t, STATE_WORDS>& a) {
    int d = 0;
    for (auto x : a) d += lab_hamming_u64(x);
    return d;
}

static std::string lab_hex_state(const std::array<uint64_t, STATE_WORDS>& s) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto x : s) oss << std::setw(16) << x;
    return oss.str();
}

static std::vector<uint8_t> lab_state_to_bytes(const std::array<uint64_t, STATE_WORDS>& s) {
    std::vector<uint8_t> out(STATE_WORDS * 8);
    for (size_t i = 0; i < STATE_WORDS; ++i) store64_le(out.data() + 8 * i, s[i]);
    return out;
}

static std::vector<uint8_t> lab_random_bytes(size_t n) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; ++i) v[i] = (uint8_t)(lab_rand_u64() & 0xFF);
    return v;
}

static std::vector<uint8_t> lab_froghash512_bytes(const uint8_t* data, size_t len, const uint64_t RC[ROUNDS][CAP_WORDS]) {
    alignas(64) uint64_t S[STATE_WORDS];
    for (size_t i = 0; i < STATE_WORDS; ++i) S[i] = 0;
    S[0] ^= 0x46524F4748415348ULL;
    S[1] ^= 0x3531322D56322D20ULL;
    permute_p1024_v2(S, RC);

    size_t off = 0;
    while (off + RATE_BYTES <= len) {
        xor_rate(S, data + off);
        permute_p1024_v2(S, RC);
        off += RATE_BYTES;
    }
    size_t tail = len - off;
    for (size_t i = 0; i < tail; ++i) xor_byte_rate(S, i, data[off + i]);
    xor_byte_rate(S, tail, 0x80);
    xor_byte_rate(S, RATE_BYTES - 1, 0x01);
    permute_p1024_v2(S, RC);

    uint8_t rate[RATE_BYTES];
    output_transform_rate(rate, S);
    std::vector<uint8_t> out(rate, rate + 64);
    secure_zero(rate, sizeof(rate));
    secure_zero(S, sizeof(S));
    return out;
}

static int lab_hamming_bytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    int d = 0;
    size_t n = std::min(a.size(), b.size());
    for (size_t i = 0; i < n; ++i) d += __builtin_popcount((unsigned)(a[i] ^ b[i]));
    return d;
}


static std::string lab_fmt_double(double x, int prec = 6) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(prec) << x;
    return oss.str();
}

static void lab_write_text(const fs::path& p, const std::string& s) {
    std::ofstream out(p);
    out << s;
}

static void lab_emit_summary_line(std::ofstream& summary, const std::string& test_name, const std::string& status, const std::string& note) {
    summary << test_name << " | " << status << " | " << note << "\n";
}

static void test_permutation_avalanche_by_round(const uint64_t RC[ROUNDS][CAP_WORDS], std::ofstream& summary) {
    CsvWriter csv(lab_results_dir / "permutation_avalanche_by_round.csv");
    csv.row("trial","flip_bit","round","hd");
    const int trials = 128;
    double avg_final = 0.0;
    for (int t = 0; t < trials; ++t) {
        auto a = lab_random_state();
        auto b = a;
        int bit = (int)(lab_rand_u64() % (STATE_WORDS * 64));
        b[(size_t)bit / 64] ^= (1ULL << (bit & 63));
        for (int r = 1; r <= ROUNDS; ++r) {
            lab_permute(a, RC, 1);
            lab_permute(b, RC, 1);
            int hd = lab_hamming_state(a, b);
            csv.row(t, bit, r, hd);
            if (r == ROUNDS) avg_final += hd;
        }
    }
    avg_final /= trials;
    lab_emit_summary_line(summary, "Permutation Avalanche by Round", "AUTOMATED", "average final HD=" + std::to_string(avg_final));
}

static void test_permutation_sac(const uint64_t RC[ROUNDS][CAP_WORDS], std::ofstream& summary) {
    CsvWriter csv(lab_results_dir / "permutation_sac.csv");
    csv.row("input_bit","output_bit","probability");
    const int trials = 512;
    std::vector<int> counts(STATE_WORDS * 64, 0);
    int input_bit = 0;
    for (int t = 0; t < trials; ++t) {
        auto a = lab_random_state();
        auto b = a;
        b[(size_t)input_bit / 64] ^= (1ULL << (input_bit & 63));
        lab_permute(a, RC);
        lab_permute(b, RC);
        for (size_t w = 0; w < STATE_WORDS; ++w) {
            uint64_t d = a[w] ^ b[w];
            for (int bit = 0; bit < 64; ++bit) counts[w * 64 + bit] += (int)((d >> bit) & 1ULL);
        }
    }
    double avg = 0.0;
    for (size_t i = 0; i < counts.size(); ++i) {
        double p = (double)counts[i] / trials;
        avg += p;
        csv.row(input_bit, (int)i, lab_fmt_double(p, 6));
    }
    avg /= counts.size();
    lab_emit_summary_line(summary, "Permutation SAC", "AUTOMATED", "average flip probability=" + std::to_string(avg));
}

static void test_permutation_bic(const uint64_t RC[ROUNDS][CAP_WORDS], std::ofstream& summary) {
    CsvWriter csv(lab_results_dir / "permutation_bic_pairs.csv");
    csv.row("pair_index","corr");
    const int trials = 256;
    const std::array<int, 8> probe_bits = {0,1,2,3,64,65,127,255};
    double accum = 0.0;
    int pairs = 0;
    for (size_t i = 0; i < probe_bits.size(); ++i) {
        for (size_t j = i + 1; j < probe_bits.size(); ++j) {
            double ex = 0.0, ey = 0.0, exy = 0.0;
            for (int t = 0; t < trials; ++t) {
                auto a = lab_random_state();
                auto b = a;
                b[(size_t)0] ^= 1ULL;
                lab_permute(a, RC);
                lab_permute(b, RC);
                uint64_t d0 = a[(size_t)probe_bits[i]/64] ^ b[(size_t)probe_bits[i]/64];
                uint64_t d1 = a[(size_t)probe_bits[j]/64] ^ b[(size_t)probe_bits[j]/64];
                double x = (double)((d0 >> (probe_bits[i]&63)) & 1ULL);
                double y = (double)((d1 >> (probe_bits[j]&63)) & 1ULL);
                ex += x; ey += y; exy += x*y;
            }
            ex /= trials; ey /= trials; exy /= trials;
            double corr = exy - ex*ey;
            csv.row((int)pairs, lab_fmt_double(corr, 9));
            accum += std::abs(corr);
            pairs++;
        }
    }
    lab_emit_summary_line(summary, "Permutation BIC", "AUTOMATED", "avg |corr|=" + std::to_string(accum / std::max(1,pairs)));
}

static void test_permutation_bit_balance(const uint64_t RC[ROUNDS][CAP_WORDS], std::ofstream& summary) {
    CsvWriter csv(lab_results_dir / "permutation_bit_balance.csv");
    csv.row("bit","probability_one");
    const int trials = 1024;
    std::vector<int> counts(STATE_WORDS * 64, 0);
    for (int t = 0; t < trials; ++t) {
        auto s = lab_random_state();
        lab_permute(s, RC);
        for (size_t w = 0; w < STATE_WORDS; ++w) {
            for (int b = 0; b < 64; ++b) counts[w*64+b] += (int)((s[w] >> b) & 1ULL);
        }
    }
    double max_dev = 0.0;
    for (size_t i = 0; i < counts.size(); ++i) {
        double p = (double)counts[i] / trials;
        max_dev = std::max(max_dev, std::abs(p - 0.5));
        csv.row((int)i, lab_fmt_double(p, 6));
    }
    lab_emit_summary_line(summary, "Permutation Bit Balance", "AUTOMATED", "max deviation from 0.5=" + std::to_string(max_dev));
}

static void test_permutation_byte_frequency(const uint64_t RC[ROUNDS][CAP_WORDS], std::ofstream& summary) {
    CsvWriter csv(lab_results_dir / "permutation_byte_frequency.csv");
    csv.row("byte_value","count");
    const int trials = 4096;
    std::array<uint64_t,256> counts{};
    for (int t = 0; t < trials; ++t) {
        auto s = lab_random_state();
        lab_permute(s, RC);
        auto bytes = lab_state_to_bytes(s);
        for (uint8_t c : bytes) counts[c]++;
    }
    double total = (double)trials * STATE_WORDS * 8.0;
    double expected = total / 256.0;
    double chisq = 0.0;
    for (int i = 0; i < 256; ++i) {
        chisq += ((double)counts[i] - expected) * ((double)counts[i] - expected) / expected;
        csv.row(i, counts[i]);
    }
    lab_emit_summary_line(summary, "Permutation Byte Frequency", "AUTOMATED", "chi-square=" + std::to_string(chisq));
}

static void test_permutation_linearity_distance(const uint64_t RC[ROUNDS][CAP_WORDS], std::ofstream& summary) {
    CsvWriter csv(lab_results_dir / "permutation_linearity_distance.csv");
    csv.row("trial","hd");
    const int trials = 512;
    double avg = 0.0;
    for (int t = 0; t < trials; ++t) {
        auto A = lab_random_state();
        auto B = lab_random_state();
        auto AxB = A;
        for (size_t i = 0; i < STATE_WORDS; ++i) AxB[i] ^= B[i];
        auto lhs = AxB;
        auto pA = A, pB = B;
        lab_permute(lhs, RC);
        lab_permute(pA, RC);
        lab_permute(pB, RC);
        for (size_t i = 0; i < STATE_WORDS; ++i) pA[i] ^= pB[i];
        int hd = lab_hamming_state(lhs, pA);
        avg += hd;
        csv.row(t, hd);
    }
    lab_emit_summary_line(summary, "Permutation Linearity Distance", "AUTOMATED", "avg HD=" + std::to_string(avg / trials));
}

static void test_permutation_fixed_points(const uint64_t RC[ROUNDS][CAP_WORDS], std::ofstream& summary) {
    const int trials = 20000;
    int fixed = 0;
    int near_fixed = 0;
    CsvWriter csv(lab_results_dir / "permutation_fixed_points.csv");
    csv.row("trial","hd_after_perm");
    for (int t = 0; t < trials; ++t) {
        auto s = lab_random_state();
        auto p = s;
        lab_permute(p, RC);
        int hd = lab_hamming_state(s, p);
        if (hd == 0) fixed++;
        if (hd <= 8) near_fixed++;
        if (t < 2000) csv.row(t, hd);
    }
    lab_emit_summary_line(summary, "Permutation Fixed/Near-Fixed Search", "AUTOMATED", "fixed=" + std::to_string(fixed) + " near_fixed<=8=" + std::to_string(near_fixed));
}

static void test_permutation_short_cycles(const uint64_t RC[ROUNDS][CAP_WORDS], std::ofstream& summary) {
    CsvWriter csv(lab_results_dir / "permutation_short_cycles.csv");
    csv.row("seed_index","cycle_detected_step_or_-1");
    const int seeds = 16;
    const int max_steps = 4096;
    int hits = 0;
    for (int sidx = 0; sidx < seeds; ++sidx) {
        auto s = lab_random_state();
        std::set<std::string> seen;
        int found = -1;
        for (int step = 0; step < max_steps; ++step) {
            auto key = lab_hex_state(s);
            if (seen.count(key)) { found = step; hits++; break; }
            seen.insert(std::move(key));
            lab_permute(s, RC);
        }
        csv.row(sidx, found);
    }
    lab_emit_summary_line(summary, "Permutation Short Cycle Smoke", "AUTOMATED", "cycle hits within window=" + std::to_string(hits));
}

static void test_permutation_zero_orbit(const uint64_t RC[ROUNDS][CAP_WORDS], std::ofstream& summary) {
    CsvWriter csv(lab_results_dir / "permutation_zero_orbit.csv");
    csv.row("round","weight");
    auto s = lab_zero_state();
    for (int r = 1; r <= 256; ++r) {
        lab_permute(s, RC);
        csv.row(r, lab_weight_state(s));
    }
    lab_emit_summary_line(summary, "Permutation Zero Orbit", "AUTOMATED", "recorded 256 rounds from zero state");
}

static void test_permutation_symmetry_smoke(const uint64_t RC[ROUNDS][CAP_WORDS], std::ofstream& summary) {
    CsvWriter csv(lab_results_dir / "permutation_symmetry_smoke.csv");
    csv.row("test","hd");
    auto s = lab_random_state();
    auto c = lab_complement_state(s);
    auto rs = lab_rotate_words_state(s, 1);
    auto ps = s, pc = c, prs = rs;
    lab_permute(ps, RC);
    lab_permute(pc, RC);
    lab_permute(prs, RC);
    auto pcs = lab_complement_state(ps);
    auto rps = lab_rotate_words_state(ps, 1);
    int hd_comp = lab_hamming_state(pc, pcs);
    int hd_rot = lab_hamming_state(prs, rps);
    csv.row("complementation_property_hd", hd_comp);
    csv.row("rotation_property_hd", hd_rot);
    lab_emit_summary_line(summary, "Permutation Symmetry Smoke", "AUTOMATED", "complement HD=" + std::to_string(hd_comp) + " rotation HD=" + std::to_string(hd_rot));
}

static void test_permutation_low_weight_propagation(const uint64_t RC[ROUNDS][CAP_WORDS], std::ofstream& summary) {
    CsvWriter csv(lab_results_dir / "permutation_low_weight_propagation.csv");
    csv.row("trial","input_weight","output_weight");
    const int trials = 256;
    double avg = 0.0;
    for (int t = 0; t < trials; ++t) {
        auto s = lab_zero_state();
        int bits = 1 + (int)(lab_rand_u64() % 4);
        for (int i = 0; i < bits; ++i) {
            int bit = (int)(lab_rand_u64() % (STATE_WORDS * 64));
            s[(size_t)bit / 64] ^= (1ULL << (bit & 63));
        }
        auto p = s;
        lab_permute(p, RC);
        int ow = lab_weight_state(p);
        avg += ow;
        csv.row(t, bits, ow);
    }
    lab_emit_summary_line(summary, "Permutation Low-Weight Propagation", "AUTOMATED", "avg output weight=" + std::to_string(avg / trials));
}

static void test_permutation_integral_balance_smoke(const uint64_t RC[ROUNDS][CAP_WORDS], std::ofstream& summary) {
    CsvWriter csv(lab_results_dir / "permutation_integral_balance_smoke.csv");
    csv.row("round","xor_all_states_low64");
    auto base = lab_zero_state();
    for (int rounds = 1; rounds <= 8; ++rounds) {
        std::array<uint64_t, STATE_WORDS> acc{};
        for (int v = 0; v < 256; ++v) {
            auto s = base;
            s[0] = (uint64_t)v;
            lab_permute(s, RC, rounds);
            for (size_t i = 0; i < STATE_WORDS; ++i) acc[i] ^= s[i];
        }
        csv.row(rounds, (unsigned long long)acc[0]);
    }
    lab_emit_summary_line(summary, "Permutation Integral Balance Smoke", "AUTOMATED", "8-round integral-style XOR traces recorded");
}

static void test_permutation_differential_smoke(const uint64_t RC[ROUNDS][CAP_WORDS], std::ofstream& summary) {
    CsvWriter csv(lab_results_dir / "permutation_differential_smoke.csv");
    csv.row("delta_bit","avg_hd_after_full");
    for (int bit = 0; bit < 16; ++bit) {
        double avg = 0.0;
        for (int t = 0; t < 128; ++t) {
            auto a = lab_random_state();
            auto b = a;
            b[0] ^= (1ULL << bit);
            lab_permute(a, RC);
            lab_permute(b, RC);
            avg += lab_hamming_state(a, b);
        }
        avg /= 128.0;
        csv.row(bit, avg);
    }
    lab_emit_summary_line(summary, "Permutation Differential Smoke", "AUTOMATED", "tracked 16 one-bit input deltas");
}

static void test_hash_determinism(const uint64_t RC[ROUNDS][CAP_WORDS], std::ofstream& summary) {
    auto msg = lab_random_bytes(777);
    auto h1 = lab_froghash512_bytes(msg.data(), msg.size(), RC);
    auto h2 = lab_froghash512_bytes(msg.data(), msg.size(), RC);
    lab_emit_summary_line(summary, "Hash Determinism", h1 == h2 ? "AUTOMATED PASS" : "AUTOMATED FAIL", "same message hashed twice");
}

static void test_hash_avalanche(const uint64_t RC[ROUNDS][CAP_WORDS], std::ofstream& summary) {
    CsvWriter csv(lab_results_dir / "hash_avalanche.csv");
    csv.row("trial","hd");
    const int trials = 512;
    double avg = 0.0;
    for (int t = 0; t < trials; ++t) {
        auto msg = lab_random_bytes(128);
        auto msg2 = msg;
        size_t idx = (size_t)(lab_rand_u64() % msg.size());
        msg2[idx] ^= (uint8_t)(1u << (lab_rand_u64() % 8));
        auto h1 = lab_froghash512_bytes(msg.data(), msg.size(), RC);
        auto h2 = lab_froghash512_bytes(msg2.data(), msg2.size(), RC);
        int hd = lab_hamming_bytes(h1, h2);
        avg += hd;
        csv.row(t, hd);
    }
    lab_emit_summary_line(summary, "Hash Avalanche", "AUTOMATED", "avg HD=" + std::to_string(avg / trials));
}

static void test_hash_bit_balance(const uint64_t RC[ROUNDS][CAP_WORDS], std::ofstream& summary) {
    CsvWriter csv(lab_results_dir / "hash_bit_balance.csv");
    csv.row("bit","probability_one");
    const int trials = 2048;
    std::vector<int> counts(512, 0);
    for (int t = 0; t < trials; ++t) {
        auto msg = lab_random_bytes(64 + (lab_rand_u64() % 256));
        auto h = lab_froghash512_bytes(msg.data(), msg.size(), RC);
        for (size_t i = 0; i < h.size(); ++i) for (int b = 0; b < 8; ++b) counts[i*8+b] += (int)((h[i] >> b) & 1u);
    }
    double max_dev = 0.0;
    for (size_t i = 0; i < counts.size(); ++i) {
        double p = (double)counts[i] / trials;
        max_dev = std::max(max_dev, std::abs(p - 0.5));
        csv.row((int)i, p);
    }
    lab_emit_summary_line(summary, "Hash Bit Balance", "AUTOMATED", "max deviation from 0.5=" + std::to_string(max_dev));
}

static void test_hash_byte_frequency(const uint64_t RC[ROUNDS][CAP_WORDS], std::ofstream& summary) {
    CsvWriter csv(lab_results_dir / "hash_byte_frequency.csv");
    csv.row("byte_value","count");
    const int trials = 4096;
    std::array<uint64_t,256> counts{};
    for (int t = 0; t < trials; ++t) {
        auto msg = lab_random_bytes((size_t)(lab_rand_u64() % 512));
        auto h = lab_froghash512_bytes(msg.data(), msg.size(), RC);
        for (auto c : h) counts[c]++;
    }
    double total = (double)trials * 64.0;
    double expected = total / 256.0;
    double chisq = 0.0;
    for (int i = 0; i < 256; ++i) {
        chisq += ((double)counts[i] - expected) * ((double)counts[i] - expected) / expected;
        csv.row(i, counts[i]);
    }
    lab_emit_summary_line(summary, "Hash Byte Frequency", "AUTOMATED", "chi-square=" + std::to_string(chisq));
}

static void test_hash_collision_smoke(const uint64_t RC[ROUNDS][CAP_WORDS], std::ofstream& summary) {
    const int trials = 20000;
    std::set<std::string> seen;
    int collisions = 0;
    for (int t = 0; t < trials; ++t) {
        auto msg = lab_random_bytes(32);
        auto h = lab_froghash512_bytes(msg.data(), msg.size(), RC);
        std::string prefix(reinterpret_cast<const char*>(h.data()), 16);
        if (!seen.insert(prefix).second) collisions++;
    }
    lab_emit_summary_line(summary, "Hash Collision Smoke (128-bit prefix)", "AUTOMATED", "prefix collisions across random set=" + std::to_string(collisions));
}

static void test_hash_near_collision_smoke(const uint64_t RC[ROUNDS][CAP_WORDS], std::ofstream& summary) {
    CsvWriter csv(lab_results_dir / "hash_near_collision_smoke.csv");
    csv.row("trial","hd");
    const int trials = 512;
    int best = 512;
    for (int t = 0; t < trials; ++t) {
        auto msg = lab_random_bytes(128);
        auto msg2 = msg;
        msg2[(size_t)(lab_rand_u64() % msg2.size())] ^= 0x01;
        auto h1 = lab_froghash512_bytes(msg.data(), msg.size(), RC);
        auto h2 = lab_froghash512_bytes(msg2.data(), msg2.size(), RC);
        int hd = lab_hamming_bytes(h1, h2);
        best = std::min(best, hd);
        csv.row(t, hd);
    }
    lab_emit_summary_line(summary, "Hash Near-Collision Smoke", "AUTOMATED", "best observed HD=" + std::to_string(best));
}

static void test_hash_second_preimage_smoke(const uint64_t RC[ROUNDS][CAP_WORDS], std::ofstream& summary) {
    auto msg = lab_random_bytes(256);
    auto target = lab_froghash512_bytes(msg.data(), msg.size(), RC);
    int accidental = 0;
    for (int t = 0; t < 10000; ++t) {
        auto alt = msg;
        alt[(size_t)(lab_rand_u64() % alt.size())] ^= (uint8_t)(1u << (lab_rand_u64() % 8));
        auto h = lab_froghash512_bytes(alt.data(), alt.size(), RC);
        if (h == target) accidental++;
    }
    lab_emit_summary_line(summary, "Hash Second-Preimage Smoke", "AUTOMATED", "accidental matches=" + std::to_string(accidental));
}

static void test_aead_existing_self_tests(const uint64_t RC[ROUNDS][CAP_WORDS], std::ofstream& summary) {
    bool ok = run_self_tests(RC, true);
    lab_emit_summary_line(summary, "AEAD Existing Self Tests", ok ? "AUTOMATED PASS" : "AUTOMATED FAIL", "reused upstream self-tests");
}

static fs::path lab_write_temp_file(const std::vector<uint8_t>& data, const std::string& name) {
    fs::create_directories(lab_results_dir / "tmp");
    fs::path p = lab_results_dir / "tmp" / name;
    std::ofstream out(p, std::ios::binary);
    out.write((const char*)data.data(), (std::streamsize)data.size());
    return p;
}

static std::vector<uint8_t> lab_read_file(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

static void test_aead_nonce_reuse_demo(const uint64_t RC[ROUNDS][CAP_WORDS], std::ofstream& summary) {
    auto pt1 = lab_random_bytes(128);
    auto pt2 = lab_random_bytes(128);
    std::vector<uint8_t> ad = {'N','R'};
    std::array<uint8_t, KEY_BYTES> key{};
    std::array<uint8_t, NONCE_BYTES> nonce{};
    for (auto &x : key) x = (uint8_t)(lab_rand_u64() & 0xFF);
    for (size_t i = 0; i < nonce.size(); ++i) nonce[i] = (uint8_t)i;

    auto in1 = lab_write_temp_file(pt1, "nr_pt1.bin");
    auto in2 = lab_write_temp_file(pt2, "nr_pt2.bin");
    fs::path out1 = lab_results_dir / "tmp" / "nr_ct1.syf";
    fs::path out2 = lab_results_dir / "tmp" / "nr_ct2.syf";

    symfrog_encrypt_file(in1.c_str(), out1.c_str(), ad.data(), ad.size(), nullptr, key.data(), nonce.data(), false, RC, true);
    symfrog_encrypt_file(in2.c_str(), out2.c_str(), ad.data(), ad.size(), nullptr, key.data(), nonce.data(), false, RC, true);

    auto f1 = lab_read_file(out1);
    auto f2 = lab_read_file(out2);
    size_t usable = std::min<size_t>(64, std::min(f1.size(), f2.size()) - HEADER_BYTES - TAG_BYTES);
    int xor_matches = 0;
    for (size_t i = 0; i < usable; ++i) {
        uint8_t c = f1[HEADER_BYTES + i] ^ f2[HEADER_BYTES + i];
        uint8_t p = pt1[i] ^ pt2[i];
        if (c == p) xor_matches++;
    }
    lab_emit_summary_line(summary, "AEAD Nonce Reuse First-Block Demo", "AUTOMATED", "matching XOR bytes in first block=" + std::to_string(xor_matches) + "/" + std::to_string(usable));
}

static void test_aead_wrong_ad_key_matrix(const uint64_t RC[ROUNDS][CAP_WORDS], std::ofstream& summary) {
    auto pt = lab_random_bytes(777);
    std::vector<uint8_t> ad = {'A','D','1'};
    std::vector<uint8_t> bad_ad = {'A','D','2'};
    std::array<uint8_t, KEY_BYTES> key{};
    std::array<uint8_t, KEY_BYTES> bad_key{};
    std::array<uint8_t, NONCE_BYTES> nonce{};
    for (auto &x : key) x = (uint8_t)(lab_rand_u64() & 0xFF);
    for (auto &x : bad_key) x = (uint8_t)(lab_rand_u64() & 0xFF);
    for (size_t i = 0; i < nonce.size(); ++i) nonce[i] = (uint8_t)(0xA0 + i);

    auto in = lab_write_temp_file(pt, "matrix_pt.bin");
    fs::path enc = lab_results_dir / "tmp" / "matrix_ct.syf";
    fs::path dec_ok = lab_results_dir / "tmp" / "matrix_dec_ok.bin";
    fs::path dec_bad_ad = lab_results_dir / "tmp" / "matrix_dec_badad.bin";
    fs::path dec_bad_key = lab_results_dir / "tmp" / "matrix_dec_badkey.bin";

    symfrog_encrypt_file(in.c_str(), enc.c_str(), ad.data(), ad.size(), nullptr, key.data(), nonce.data(), false, RC, true);
    bool ok = symfrog_decrypt_file(enc.c_str(), dec_ok.c_str(), ad.data(), ad.size(), nullptr, key.data(), false, RC, true);
    bool bad_ad_ok = symfrog_decrypt_file(enc.c_str(), dec_bad_ad.c_str(), bad_ad.data(), bad_ad.size(), nullptr, key.data(), false, RC, true);
    bool bad_key_ok = symfrog_decrypt_file(enc.c_str(), dec_bad_key.c_str(), ad.data(), ad.size(), nullptr, bad_key.data(), false, RC, true);

    lab_emit_summary_line(summary, "AEAD Wrong AD/Key Matrix", (ok && !bad_ad_ok && !bad_key_ok) ? "AUTOMATED PASS" : "AUTOMATED FAIL",
                          std::string("ok=") + (ok?"1":"0") + " bad_ad=" + (bad_ad_ok?"1":"0") + " bad_key=" + (bad_key_ok?"1":"0"));
}

static void test_existing_benchmarks(const uint64_t RC[ROUNDS][CAP_WORDS], std::ofstream& summary) {
    run_benchmarks(RC);
    lab_emit_summary_line(summary, "Existing Benchmarks", "AUTOMATED", "ran upstream permutation+AEAD benchmarks");
}

static void emit_perm_stream(const uint64_t RC[ROUNDS][CAP_WORDS], uint64_t bytes_to_emit) {
    auto s = lab_random_state();
    std::vector<uint8_t> block(STATE_WORDS * 8);
    while (bytes_to_emit > 0) {
        lab_permute(s, RC);
        for (size_t i = 0; i < STATE_WORDS; ++i) store64_le(block.data() + 8*i, s[i]);
        size_t n = (size_t)std::min<uint64_t>(bytes_to_emit, block.size());
        std::cout.write((const char*)block.data(), (std::streamsize)n);
        bytes_to_emit -= n;
    }
}

static void emit_hash_stream(const uint64_t RC[ROUNDS][CAP_WORDS], uint64_t bytes_to_emit) {
    uint64_t counter = 0;
    while (bytes_to_emit > 0) {
        std::array<uint8_t, 64> msg{};
        for (size_t i = 0; i < 8; ++i) msg[i] = (uint8_t)((counter >> (8*i)) & 0xFF);
        auto h = lab_froghash512_bytes(msg.data(), msg.size(), RC);
        size_t n = (size_t)std::min<uint64_t>(bytes_to_emit, h.size());
        std::cout.write((const char*)h.data(), (std::streamsize)n);
        bytes_to_emit -= n;
        counter++;
    }
}

static std::string checklist_markdown() {
    return R"MD(# SymFrog Full Test Checklist

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
)MD";
}

static void write_external_scripts() {
    fs::create_directories(lab_results_dir / "scripts");

    lab_write_text(lab_results_dir / "scripts" / "run_dieharder.sh", R"(#!/usr/bin/env bash
set -euo pipefail
BYTES="${1:-104857600}"
./symfrog_full_suite --emit-hash-stream "$BYTES" | dieharder -a -g 200
)");

    lab_write_text(lab_results_dir / "scripts" / "run_practrand.sh", R"(#!/usr/bin/env bash
set -euo pipefail
BYTES="${1:-1073741824}"
./symfrog_full_suite --emit-hash-stream "$BYTES" | RNG_test stdin64
)");

    lab_write_text(lab_results_dir / "scripts" / "run_nist_sts.sh", R"(#!/usr/bin/env bash
set -euo pipefail
BYTES="${1:-12500000}"
OUT="nist_input.bin"
./symfrog_full_suite --emit-hash-stream "$BYTES" > "$OUT"
echo "Feed $OUT into the NIST STS harness."
)");

    lab_write_text(lab_results_dir / "scripts" / "build_sanitizers.sh", R"(#!/usr/bin/env bash
set -euo pipefail
clang++ -std=c++23 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer symfrog_full_suite.cpp -o symfrog_full_suite_asan -lsodium -lcrypto
)");

    lab_write_text(lab_results_dir / "scripts" / "build_libfuzzer.sh", R"(#!/usr/bin/env bash
set -euo pipefail
echo "Stub: wire a fuzz target that reaches parsers, enc/dec, and file ingest paths."
)");

    lab_write_text(lab_results_dir / "scripts" / "build_afl_stub.sh", R"(#!/usr/bin/env bash
set -euo pipefail
echo "Stub: build an AFL++ target around decrypt / parse / hash entry points."
)");
}

static void run_full_suite(const uint64_t RC[ROUNDS][CAP_WORDS]) {
    fs::create_directories(lab_results_dir);
    fs::create_directories(lab_results_dir / "tmp");

    std::ofstream summary(lab_results_dir / "SUMMARY.txt");
    summary << "Test | Status | Note\n";
    summary << "---|---|---\n";

    test_permutation_avalanche_by_round(RC, summary);
    test_permutation_sac(RC, summary);
    test_permutation_bic(RC, summary);
    test_permutation_bit_balance(RC, summary);
    test_permutation_byte_frequency(RC, summary);
    test_permutation_linearity_distance(RC, summary);
    test_permutation_fixed_points(RC, summary);
    test_permutation_short_cycles(RC, summary);
    test_permutation_zero_orbit(RC, summary);
    test_permutation_symmetry_smoke(RC, summary);
    test_permutation_low_weight_propagation(RC, summary);
    test_permutation_integral_balance_smoke(RC, summary);
    test_permutation_differential_smoke(RC, summary);

    test_hash_determinism(RC, summary);
    test_hash_avalanche(RC, summary);
    test_hash_bit_balance(RC, summary);
    test_hash_byte_frequency(RC, summary);
    test_hash_collision_smoke(RC, summary);
    test_hash_near_collision_smoke(RC, summary);
    test_hash_second_preimage_smoke(RC, summary);

    test_aead_existing_self_tests(RC, summary);
    test_aead_nonce_reuse_demo(RC, summary);
    test_aead_wrong_ad_key_matrix(RC, summary);
    test_existing_benchmarks(RC, summary);

    summary.close();

    lab_write_text(lab_results_dir / "CHECKLIST.md", checklist_markdown());
    write_external_scripts();

    std::cout << "Results written to " << lab_results_dir << "\n";
}

int main(int argc, char** argv) {
    if (sodium_init() < 0) {
        std::cerr << "libsodium init failed\n";
        return 2;
    }

    uint64_t RC[ROUNDS][CAP_WORDS];
    gen_round_constants(RC);

    if (argc >= 3 && std::string_view(argv[1]) == "--emit-perm-stream") {
        emit_perm_stream(RC, std::stoull(argv[2]));
        return 0;
    }
    if (argc >= 3 && std::string_view(argv[1]) == "--emit-hash-stream") {
        emit_hash_stream(RC, std::stoull(argv[2]));
        return 0;
    }

    run_full_suite(RC);
    return 0;
}
