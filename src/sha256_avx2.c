#ifndef SHA256_AVX2_LICENSE
/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Rhett Creighton */
#define SHA256_AVX2_LICENSE
#endif
#ifdef __AVX2__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#include "sha2.h"
#include <immintrin.h>

/* SHA-256 round constants (K) for AVX2 path */
static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/* Rotate right (circular right shift) for 4-way parallel lanes in lower half of __m256i */
static inline __m256i ror32_4(__m256i v, int n) {
    return _mm256_or_si256(_mm256_srli_epi32(v, n), _mm256_slli_epi32(v, 32 - n));
}

/* SHA-256 small sigma functions for message schedule */
static inline __m256i gamma0_4(__m256i x) {
    return _mm256_xor_si256(_mm256_xor_si256(ror32_4(x, 7), ror32_4(x, 18)), _mm256_srli_epi32(x, 3));
}

static inline __m256i gamma1_4(__m256i x) {
    return _mm256_xor_si256(_mm256_xor_si256(ror32_4(x, 17), ror32_4(x, 19)), _mm256_srli_epi32(x, 10));
}

/* SHA-256 large sigma functions */
static inline __m256i sigma0_4(__m256i x) {
    return _mm256_xor_si256(_mm256_xor_si256(ror32_4(x, 2), ror32_4(x, 13)), ror32_4(x, 22));
}
static inline __m256i sigma1_4(__m256i x) {
    return _mm256_xor_si256(_mm256_xor_si256(ror32_4(x, 6), ror32_4(x, 11)), ror32_4(x, 25));
}

/* SHA-256 choice and majority functions */
static inline __m256i ch_4(__m256i x, __m256i y, __m256i z) {
    return _mm256_xor_si256(_mm256_and_si256(x, y), _mm256_andnot_si256(x, z));
}
static inline __m256i maj_4(__m256i x, __m256i y, __m256i z) {
    __m256i t1 = _mm256_and_si256(x, y);
    __m256i t2 = _mm256_and_si256(x, z);
    __m256i t3 = _mm256_and_si256(y, z);
    return _mm256_xor_si256(_mm256_xor_si256(t1, t2), t3);
}

/**
 * Prototype: process four independent 512-bit blocks in parallel using AVX2
 * states0..3: initial H0..H7 for each of four contexts
 * blocks0..3: pointers to four 64-byte message blocks
 */
void sha256_process4_avx2(
    uint32_t state0[8], uint32_t state1[8],
    uint32_t state2[8], uint32_t state3[8],
    const uint8_t *block0, const uint8_t *block1,
    const uint8_t *block2, const uint8_t *block3)
{
    __m256i W[64];
    // Load initial working variables from four states into lanes 0-3
    __m256i a = _mm256_setr_epi32(state0[0], state1[0], state2[0], state3[0], 0, 0, 0, 0);
    __m256i b = _mm256_setr_epi32(state0[1], state1[1], state2[1], state3[1], 0, 0, 0, 0);
    __m256i c = _mm256_setr_epi32(state0[2], state1[2], state2[2], state3[2], 0, 0, 0, 0);
    __m256i d = _mm256_setr_epi32(state0[3], state1[3], state2[3], state3[3], 0, 0, 0, 0);
    __m256i e = _mm256_setr_epi32(state0[4], state1[4], state2[4], state3[4], 0, 0, 0, 0);
    __m256i f = _mm256_setr_epi32(state0[5], state1[5], state2[5], state3[5], 0, 0, 0, 0);
    __m256i g = _mm256_setr_epi32(state0[6], state1[6], state2[6], state3[6], 0, 0, 0, 0);
    __m256i h = _mm256_setr_epi32(state0[7], state1[7], state2[7], state3[7], 0, 0, 0, 0);

    // Load first 16 words (big-endian) into W[0..15]
    for (int i = 0; i < 16; i++) {
        uint32_t w0 = ((uint32_t)block0[i*4] << 24) | ((uint32_t)block0[i*4+1] << 16)
                    | ((uint32_t)block0[i*4+2] << 8)  |  (uint32_t)block0[i*4+3];
        uint32_t w1 = ((uint32_t)block1[i*4] << 24) | ((uint32_t)block1[i*4+1] << 16)
                    | ((uint32_t)block1[i*4+2] << 8)  |  (uint32_t)block1[i*4+3];
        uint32_t w2 = ((uint32_t)block2[i*4] << 24) | ((uint32_t)block2[i*4+1] << 16)
                    | ((uint32_t)block2[i*4+2] << 8)  |  (uint32_t)block2[i*4+3];
        uint32_t w3 = ((uint32_t)block3[i*4] << 24) | ((uint32_t)block3[i*4+1] << 16)
                    | ((uint32_t)block3[i*4+2] << 8)  |  (uint32_t)block3[i*4+3];
        W[i] = _mm256_setr_epi32(w0, w1, w2, w3, 0, 0, 0, 0);
    }

    // Extend message schedule W[16..63]
    for (int i = 16; i < 64; i++) {
        __m256i s1 = gamma1_4(W[i - 2]);
        __m256i s0 = gamma0_4(W[i - 15]);
        W[i] = _mm256_add_epi32(_mm256_add_epi32(_mm256_add_epi32(s1, W[i - 7]), s0), W[i - 16]);
    }

    // 64-round compression loop
    for (int i = 0; i < 64; i++) {
        __m256i Kvec = _mm256_set1_epi32(K256[i]);
        __m256i T1 = _mm256_add_epi32(
            _mm256_add_epi32(_mm256_add_epi32(h, sigma1_4(e)), ch_4(e, f, g)),
            _mm256_add_epi32(Kvec, W[i])
        );
        __m256i T2 = _mm256_add_epi32(sigma0_4(a), maj_4(a, b, c));
        h = g; g = f; f = e;
        e = _mm256_add_epi32(d, T1);
        d = c; c = b; b = a;
        a = _mm256_add_epi32(T1, T2);
    }

    // Add compressed chunk back into state arrays
    uint32_t out[8];
    _mm256_storeu_si256((__m256i*)out, a);
    state0[0] += out[0]; state1[0] += out[1]; state2[0] += out[2]; state3[0] += out[3];
    _mm256_storeu_si256((__m256i*)out, b);
    state0[1] += out[0]; state1[1] += out[1]; state2[1] += out[2]; state3[1] += out[3];
    _mm256_storeu_si256((__m256i*)out, c);
    state0[2] += out[0]; state1[2] += out[1]; state2[2] += out[2]; state3[2] += out[3];
    _mm256_storeu_si256((__m256i*)out, d);
    state0[3] += out[0]; state1[3] += out[1]; state2[3] += out[2]; state3[3] += out[3];
    _mm256_storeu_si256((__m256i*)out, e);
    state0[4] += out[0]; state1[4] += out[1]; state2[4] += out[2]; state3[4] += out[3];
    _mm256_storeu_si256((__m256i*)out, f);
    state0[5] += out[0]; state1[5] += out[1]; state2[5] += out[2]; state3[5] += out[3];
    _mm256_storeu_si256((__m256i*)out, g);
    state0[6] += out[0]; state1[6] += out[1]; state2[6] += out[2]; state3[6] += out[3];
    _mm256_storeu_si256((__m256i*)out, h);
    state0[7] += out[0]; state1[7] += out[1]; state2[7] += out[2]; state3[7] += out[3];
}
#pragma GCC diagnostic pop
#else
// When AVX2 not available, provide non-empty translation unit
typedef int sha256_avx2_not_supported;
#endif // __AVX2__
