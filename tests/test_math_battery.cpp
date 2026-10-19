// Additional mathematical invariants for P1024-v3. Requires a normal SymFrog build environment.
// Example: clang++ -std=c++23 -O2 -I/usr/include tests/test_math_battery.cpp -o test_math_battery -lsodium -lcrypto
#define main symfrog_application_main
#include "../src/symfrog512.cpp"
#undef main
#include <array>
#include <random>
#include <iostream>
#include <iomanip>
#include <cmath>
#include <chrono>
#include <limits>

using State = std::array<uint64_t,STATE_WORDS>;
static std::mt19937_64 mt(0xDAE5202600000512ULL);
static void random_state(State& s){for(auto& x:s)x=mt();}
static int hd(const State& x,const State& y){int v=0;for(size_t i=0;i<STATE_WORDS;++i)v+=std::popcount(x[i]^y[i]);return v;}
static void require(bool x,const char* why){ if(!x){std::cerr<<"FAILED "<<why<<"\n";std::exit(1);} }

static uint8_t chi_small(uint8_t x){
    uint64_t a[16]{};for(unsigned i=0;i<4;++i)a[i]=(x>>i)&1U;
    chi_layer(a);
    uint8_t y=0;
    for(unsigned i=0;i<4;++i)y|=uint8_t((a[i]&1ULL)<<i);
    return y;
}
int main(){
    require(sodium_init()>=0,"libsodium initialization");
    uint64_t rc[ROUNDS][CAP_WORDS];gen_round_constants(rc);
    std::array<uint8_t,16> chi{};
    unsigned used=0;
    for(int x=0;x<16;++x){chi[x]=chi_small(uint8_t(x));require(!(used & (1U<<chi[x])),"chi bijection");used|=1U<<chi[x];}
    int ddtmax=0;
    for(int dx=1;dx<16;++dx){int hist[16]{};for(int x=0;x<16;++x)++hist[chi[x]^chi[x^dx]];for(int n:hist)ddtmax=std::max(ddtmax,n);}
    int latmax=0;
    for(int a=1;a<16;++a)for(int b=1;b<16;++b){
       int sum=0;for(int x=0;x<16;++x){int p=std::popcount(unsigned(a&x))^std::popcount(unsigned(b&chi[x]));sum+=(p&1)?-1:1;}
       latmax=std::max(latmax,std::abs(sum));
    }
    // Check individual bijective layers and whole permutation with distinct inputs.
    size_t layer_tests=0,perm_inv_tests=0;
    for(int t=0;t<50000;++t){
        State orig{},temp{};random_state(orig);
        temp=orig;chi_layer(temp.data());inverse_chi_layer(temp.data());require(temp==orig,"chi inverse");
        temp=orig;kick_layer(temp.data());inverse_kick_layer(temp.data());require(temp==orig,"kick inverse");
        temp=orig;rotate_shuffle(temp.data());inverse_rotate_shuffle(temp.data());require(temp==orig,"rotate shuffle inverse");
        layer_tests+=3;
        temp=orig;permute_p1024(temp.data(),rc,VERSION_CURRENT);inverse_permute_p1024_v3(temp.data(),rc);
        require(temp==orig,"permutation inverse random state");++perm_inv_tests;
    }
    for(int bit=0;bit<1024;++bit){
        State base{};base[bit>>6]=1ULL<<(bit%64);
        State t=base;permute_p1024(t.data(),rc,VERSION_CURRENT);inverse_permute_p1024_v3(t.data(),rc);require(t==base,"basis state inverse");
        for(auto& x:base)x=~x;
        t=base;permute_p1024(t.data(),rc,VERSION_CURRENT);inverse_permute_p1024_v3(t.data(),rc);require(t==base,"complement basis inverse");perm_inv_tests+=2;
    }
    // Random single-bit input differences, with fixed round constants.
    constexpr int N=8000;
    double hd_sum=0,hd_sq=0;
    int mn=1025,mx=0;
    std::array<unsigned,1024> bit_counts{};
    for(int t=0;t<N;++t){
        State a{},b{};random_state(a);b=a;
        int flipped=int(mt()%1024);b[flipped>>6]^=(1ULL<<(flipped%64));
        permute_p1024(a.data(),rc,VERSION_CURRENT);
        permute_p1024(b.data(),rc,VERSION_CURRENT);
        int h=hd(a,b);hd_sum+=h;hd_sq+=double(h)*h;mn=std::min(mn,h);mx=std::max(mx,h);
        for(unsigned i=0;i<1024;++i)bit_counts[i]+=unsigned((a[i>>6]^b[i>>6])>>(i%64)&1ULL);
    }
    double avg=hd_sum/N;
    double sd=std::sqrt(hd_sq/N-avg*avg);
    double maxdev=0.0;
    for(unsigned n:bit_counts)maxdev=std::max(maxdev,std::abs(double(n)/N-0.5));
    // Loose gross error limits, not a randomness certification.
    require(avg>503 && avg<521,"mean avalanche deviates dramatically from ideal half");
    require(maxdev<0.05,"output bit-position avalanche deviates dramatically");
    // v3 legacy identity: the XOR-related key/nonce pair had an equal initial state.
    // v4/v5 must reject this exact deterministic equivalence; test also a known
    // RFC 5869 HKDF-SHA512 reference vector in tests/test_v4_init.cpp.
    std::array<uint8_t,KEY_BYTES> key{},related{};
    std::array<uint8_t,NONCE_BYTES> nonce{},other{};
    for(auto& x:key)x=uint8_t(mt());for(auto& x:nonce)x=uint8_t(mt());
    related=key;other=nonce;
    for(unsigned i=0;i<NONCE_BYTES;++i){uint8_t d=uint8_t((i*47+9)&255);related[96+i]^=d;other[i]^=d;}
    State initial1{},initial2{};
    init_state_with_key_nonce(initial1.data(),key.data(),nonce.data(),VERSION_BIJECTIVE);
    init_state_with_key_nonce(initial2.data(),related.data(),other.data(),VERSION_BIJECTIVE);
    require(initial1==initial2,"legacy v3 related key/nonce equivalence changed");
    init_state_with_key_nonce(initial1.data(),key.data(),nonce.data(),VERSION_CURRENT);
    init_state_with_key_nonce(initial2.data(),related.data(),other.data(),VERSION_CURRENT);
    require(initial1!=initial2,"v5 still exhibits legacy related key/nonce equivalence");
    std::cout<<std::fixed<<std::setprecision(6)
      <<"PASS chi_sbox_unique=16 ddt_max="<<ddtmax<<" lat_max_abs="<<latmax<<"\n"
      <<"PASS per_layer_inverse_checks="<<layer_tests<<"\n"
      <<"PASS full_permutation_inverse_checks="<<perm_inv_tests<<"\n"
      <<"PASS permutation_one_bit_avalanche_samples="<<N<<" mean_hd="<<avg
      <<" min="<<mn<<" max="<<mx<<" sd="<<sd<<" max_bit_position_deviation="<<maxdev<<"\n"
      <<"PASS legacy_v3_related_pair_equal=true v5_related_pair_equal=false\n";
    return 0;
}
