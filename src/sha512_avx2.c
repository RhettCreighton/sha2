/*
 * sha512_avx2.c
 *
 * AVX2 parallel implementation of SHA-512 (4-way)
 */
#ifndef SHA512_AVX2_LICENSE
/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Rhett Creighton */
#define SHA512_AVX2_LICENSE
#endif
#if defined(__AVX2__)
#include "sha2.h"
#include <immintrin.h>
#include <string.h>

// SHA-512 round constants
static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

static inline __m256i rotr64_4(__m256i v, int r) {
    return _mm256_or_si256(_mm256_srli_epi64(v, r), _mm256_slli_epi64(v, 64 - r));
}

static inline __m256i gamma0_4(__m256i x) {
    return _mm256_xor_si256(
        _mm256_xor_si256(rotr64_4(x,1), rotr64_4(x,8)),
        _mm256_srli_epi64(x,7)
    );
}
static inline __m256i gamma1_4(__m256i x) {
    return _mm256_xor_si256(
        _mm256_xor_si256(rotr64_4(x,19), rotr64_4(x,61)),
        _mm256_srli_epi64(x,6)
    );
}
static inline __m256i sigma0_4(__m256i x) {
    return _mm256_xor_si256(
        _mm256_xor_si256(rotr64_4(x,28), rotr64_4(x,34)),
        rotr64_4(x,39)
    );
}
static inline __m256i sigma1_4(__m256i x) {
    return _mm256_xor_si256(
        _mm256_xor_si256(rotr64_4(x,14), rotr64_4(x,18)),
        rotr64_4(x,41)
    );
}
static inline __m256i ch_4(__m256i x, __m256i y, __m256i z) {
    return _mm256_xor_si256(_mm256_and_si256(x,y), _mm256_andnot_si256(x,z));
}
static inline __m256i maj_4(__m256i x, __m256i y, __m256i z) {
    __m256i t1 = _mm256_and_si256(x,y);
    __m256i t2 = _mm256_and_si256(x,z);
    __m256i t3 = _mm256_and_si256(y,z);
    return _mm256_xor_si256(_mm256_xor_si256(t1,t2),t3);
}

void sha512_process4_avx2(
    uint64_t state0[8], uint64_t state1[8], uint64_t state2[8], uint64_t state3[8],
    const uint8_t *block0, const uint8_t *block1,
    const uint8_t *block2, const uint8_t *block3
) {
    __m256i W[80];
    __m256i a = _mm256_setr_epi64x(state0[0],state1[0],state2[0],state3[0]);
    __m256i b = _mm256_setr_epi64x(state0[1],state1[1],state2[1],state3[1]);
    __m256i c = _mm256_setr_epi64x(state0[2],state1[2],state2[2],state3[2]);
    __m256i d = _mm256_setr_epi64x(state0[3],state1[3],state2[3],state3[3]);
    __m256i e = _mm256_setr_epi64x(state0[4],state1[4],state2[4],state3[4]);
    __m256i f = _mm256_setr_epi64x(state0[5],state1[5],state2[5],state3[5]);
    __m256i g = _mm256_setr_epi64x(state0[6],state1[6],state2[6],state3[6]);
    __m256i h = _mm256_setr_epi64x(state0[7],state1[7],state2[7],state3[7]);
    for (int i = 0; i < 16; i++) {
        uint64_t w0 = ((uint64_t)block0[i*8] <<56) |((uint64_t)block0[i*8+1]<<48)
                    |((uint64_t)block0[i*8+2]<<40)|((uint64_t)block0[i*8+3]<<32)
                    |((uint64_t)block0[i*8+4]<<24)|((uint64_t)block0[i*8+5]<<16)
                    |((uint64_t)block0[i*8+6]<< 8)|((uint64_t)block0[i*8+7]    );
        uint64_t w1 = ((uint64_t)block1[i*8] <<56) |((uint64_t)block1[i*8+1]<<48)
                    |((uint64_t)block1[i*8+2]<<40)|((uint64_t)block1[i*8+3]<<32)
                    |((uint64_t)block1[i*8+4]<<24)|((uint64_t)block1[i*8+5]<<16)
                    |((uint64_t)block1[i*8+6]<< 8)|((uint64_t)block1[i*8+7]    );
        uint64_t w2 = ((uint64_t)block2[i*8] <<56) |((uint64_t)block2[i*8+1]<<48)
                    |((uint64_t)block2[i*8+2]<<40)|((uint64_t)block2[i*8+3]<<32)
                    |((uint64_t)block2[i*8+4]<<24)|((uint64_t)block2[i*8+5]<<16)
                    |((uint64_t)block2[i*8+6]<< 8)|((uint64_t)block2[i*8+7]    );
        uint64_t w3 = ((uint64_t)block3[i*8] <<56) |((uint64_t)block3[i*8+1]<<48)
                    |((uint64_t)block3[i*8+2]<<40)|((uint64_t)block3[i*8+3]<<32)
                    |((uint64_t)block3[i*8+4]<<24)|((uint64_t)block3[i*8+5]<<16)
                    |((uint64_t)block3[i*8+6]<< 8)|((uint64_t)block3[i*8+7]    );
        W[i] = _mm256_setr_epi64x(w0,w1,w2,w3);
    }
    for (int i = 16; i < 80; i++) {
        __m256i s1 = gamma1_4(W[i-2]);
        __m256i s0 = gamma0_4(W[i-15]);
        W[i] = _mm256_add_epi64(_mm256_add_epi64(_mm256_add_epi64(s1, W[i-7]), s0), W[i-16]);
    }
    for (int i = 0; i < 80; i++) {
        __m256i T1 = _mm256_add_epi64(
            _mm256_add_epi64(_mm256_add_epi64(h, sigma1_4(e)), ch_4(e,f,g)),
            _mm256_add_epi64(_mm256_set1_epi64x(K512[i]), W[i])
        );
        __m256i T2 = _mm256_add_epi64(sigma0_4(a), maj_4(a,b,c));
        h = g; g = f; f = e;
        e = _mm256_add_epi64(d, T1);
        d = c; c = b; b = a;
        a = _mm256_add_epi64(T1, T2);
    }
    uint64_t out[4];
    _mm256_storeu_si256((__m256i*)out, a);
    state0[0]+=out[0]; state1[0]+=out[1]; state2[0]+=out[2]; state3[0]+=out[3];
    _mm256_storeu_si256((__m256i*)out, b);
    state0[1]+=out[0]; state1[1]+=out[1]; state2[1]+=out[2]; state3[1]+=out[3];
    _mm256_storeu_si256((__m256i*)out, c);
    state0[2]+=out[0]; state1[2]+=out[1]; state2[2]+=out[2]; state3[2]+=out[3];
    _mm256_storeu_si256((__m256i*)out, d);
    state0[3]+=out[0]; state1[3]+=out[1]; state2[3]+=out[2]; state3[3]+=out[3];
    _mm256_storeu_si256((__m256i*)out, e);
    state0[4]+=out[0]; state1[4]+=out[1]; state2[4]+=out[2]; state3[4]+=out[3];
    _mm256_storeu_si256((__m256i*)out, f);
    state0[5]+=out[0]; state1[5]+=out[1]; state2[5]+=out[2]; state3[5]+=out[3];
    _mm256_storeu_si256((__m256i*)out, g);
    state0[6]+=out[0]; state1[6]+=out[1]; state2[6]+=out[2]; state3[6]+=out[3];
    _mm256_storeu_si256((__m256i*)out, h);
    state0[7]+=out[0]; state1[7]+=out[1]; state2[7]+=out[2]; state3[7]+=out[3];
}

#else
// When AVX2 not available, provide non-empty translation unit
typedef int sha512_avx2_not_supported;
#endif // __AVX2__
