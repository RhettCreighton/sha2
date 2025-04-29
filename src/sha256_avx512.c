/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Rhett Creighton */

/*
 * sha256_avx512.c
 *
 * SHA-256 compression using AVX-512 SHA extensions (8-way parallel)
 */
#include "sha2.h"
#if defined(__AVX512F__) && defined(__SHA__)
#include <immintrin.h>

// Rotate right 32-bit lanes in 512-bit vector
static inline __m512i ror32_8(__m512i x, int r) {
    return _mm512_or_epi32(_mm512_srli_epi32(x, r), _mm512_slli_epi32(x, 32 - r));
}

// SHA-256 large sigma functions
static inline __m512i sigma0_8(__m512i x) {
    return _mm512_xor_epi32(
        _mm512_xor_epi32(ror32_8(x, 2), ror32_8(x, 13)),
        ror32_8(x, 22)
    );
}
static inline __m512i sigma1_8(__m512i x) {
    return _mm512_xor_epi32(
        _mm512_xor_epi32(ror32_8(x, 6), ror32_8(x, 11)),
        ror32_8(x, 25)
    );
}

// SHA-256 small sigma (message schedule)
static inline __m512i gamma0_8(__m512i x) {
    return _mm512_xor_epi32(
        _mm512_xor_epi32(ror32_8(x, 7), ror32_8(x, 18)),
        _mm512_srli_epi32(x, 3)
    );
}
static inline __m512i gamma1_8(__m512i x) {
    return _mm512_xor_epi32(
        _mm512_xor_epi32(ror32_8(x, 17), ror32_8(x, 19)),
        _mm512_srli_epi32(x, 10)
    );
}

// SHA-256 choice and majority
static inline __m512i ch_8(__m512i x, __m512i y, __m512i z) {
    return _mm512_xor_epi32(_mm512_and_epi32(x, y), _mm512_andnot_epi32(x, z));
}
static inline __m512i maj_8(__m512i x, __m512i y, __m512i z) {
    __m512i t1 = _mm512_and_epi32(x, y);
    __m512i t2 = _mm512_and_epi32(x, z);
    __m512i t3 = _mm512_and_epi32(y, z);
    return _mm512_xor_epi32(_mm512_xor_epi32(t1, t2), t3);
}

// SHA-256 round constants
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

/**
 * @brief Process eight independent 512-bit blocks in parallel using AVX-512 SHA
 * @param state0..7 Eight 8-word state arrays
 * @param block0..7 Eight pointers to 64-byte blocks
 */
void sha256_process8_avx512(
    uint32_t state0[8], uint32_t state1[8], uint32_t state2[8], uint32_t state3[8],
    uint32_t state4[8], uint32_t state5[8], uint32_t state6[8], uint32_t state7[8],
    const uint8_t *block0, const uint8_t *block1, const uint8_t *block2, const uint8_t *block3,
    const uint8_t *block4, const uint8_t *block5, const uint8_t *block6, const uint8_t *block7
) {
    __m512i W[64];
    // Initialize working variables a-h in lanes 0..7
    __m512i a = _mm512_setr_epi32(
        state0[0], state1[0], state2[0], state3[0], state4[0], state5[0], state6[0], state7[0],
        0,0,0,0,0,0,0,0
    );
    __m512i b = _mm512_setr_epi32(
        state0[1], state1[1], state2[1], state3[1], state4[1], state5[1], state6[1], state7[1],
        0,0,0,0,0,0,0,0
    );
    __m512i c = _mm512_setr_epi32(
        state0[2], state1[2], state2[2], state3[2], state4[2], state5[2], state6[2], state7[2],
        0,0,0,0,0,0,0,0
    );
    __m512i d = _mm512_setr_epi32(
        state0[3], state1[3], state2[3], state3[3], state4[3], state5[3], state6[3], state7[3],
        0,0,0,0,0,0,0,0
    );
    __m512i e = _mm512_setr_epi32(
        state0[4], state1[4], state2[4], state3[4], state4[4], state5[4], state6[4], state7[4],
        0,0,0,0,0,0,0,0
    );
    __m512i f = _mm512_setr_epi32(
        state0[5], state1[5], state2[5], state3[5], state4[5], state5[5], state6[5], state7[5],
        0,0,0,0,0,0,0,0
    );
    __m512i g = _mm512_setr_epi32(
        state0[6], state1[6], state2[6], state3[6], state4[6], state5[6], state6[6], state7[6],
        0,0,0,0,0,0,0,0
    );
    __m512i h = _mm512_setr_epi32(
        state0[7], state1[7], state2[7], state3[7], state4[7], state5[7], state6[7], state7[7],
        0,0,0,0,0,0,0,0
    );

    // Load message blocks (big-endian) into W[0..15]
    for (int i = 0; i < 16; i++) {
        uint32_t w0 = (uint32_t)block0[i*4] << 24 | (uint32_t)block0[i*4+1] << 16
                    | (uint32_t)block0[i*4+2] << 8  | (uint32_t)block0[i*4+3];
        uint32_t w1 = (uint32_t)block1[i*4] << 24 | (uint32_t)block1[i*4+1] << 16
                    | (uint32_t)block1[i*4+2] << 8  | (uint32_t)block1[i*4+3];
        uint32_t w2 = (uint32_t)block2[i*4] << 24 | (uint32_t)block2[i*4+1] << 16
                    | (uint32_t)block2[i*4+2] << 8  | (uint32_t)block2[i*4+3];
        uint32_t w3 = (uint32_t)block3[i*4] << 24 | (uint32_t)block3[i*4+1] << 16
                    | (uint32_t)block3[i*4+2] << 8  | (uint32_t)block3[i*4+3];
        uint32_t w4 = (uint32_t)block4[i*4] << 24 | (uint32_t)block4[i*4+1] << 16
                    | (uint32_t)block4[i*4+2] << 8  | (uint32_t)block4[i*4+3];
        uint32_t w5 = (uint32_t)block5[i*4] << 24 | (uint32_t)block5[i*4+1] << 16
                    | (uint32_t)block5[i*4+2] << 8  | (uint32_t)block5[i*4+3];
        uint32_t w6 = (uint32_t)block6[i*4] << 24 | (uint32_t)block6[i*4+1] << 16
                    | (uint32_t)block6[i*4+2] << 8  | (uint32_t)block6[i*4+3];
        uint32_t w7 = (uint32_t)block7[i*4] << 24 | (uint32_t)block7[i*4+1] << 16
                    | (uint32_t)block7[i*4+2] << 8  | (uint32_t)block7[i*4+3];
        W[i] = _mm512_setr_epi32(w0,w1,w2,w3,w4,w5,w6,w7, 0,0,0,0,0,0,0,0);
    }

    // Message schedule W[16..63]
    for (int i = 16; i < 64; i++) {
        __m512i s1 = gamma1_8(W[i - 2]);
        __m512i s0 = gamma0_8(W[i - 15]);
        W[i] = _mm512_add_epi32(
            _mm512_add_epi32(_mm512_add_epi32(s1, W[i - 7]), s0),
            W[i - 16]
        );
    }

    // Compression rounds
    for (int i = 0; i < 64; i++) {
        __m512i msg = W[i];
        __m512i T1 = _mm512_add_epi32(
            _mm512_add_epi32(_mm512_add_epi32(h, sigma1_8(e)), ch_8(e,f,g)),
            _mm512_add_epi32(_mm512_set1_epi32(K256[i]), msg)
        );
        __m512i T2 = _mm512_add_epi32(sigma0_8(a), maj_8(a,b,c));
        h = g; g = f; f = e;
        e = _mm512_add_epi32(d, T1);
        d = c; c = b; b = a;
        a = _mm512_add_epi32(T1, T2);
    }

    // Add back to state arrays
    uint32_t out[16];
    _mm512_storeu_si512((__m512i*)out, a);
    state0[0] += out[0]; state1[0] += out[1]; state2[0] += out[2]; state3[0] += out[3];
    state4[0] += out[4]; state5[0] += out[5]; state6[0] += out[6]; state7[0] += out[7];
    _mm512_storeu_si512((__m512i*)out, b);
    state0[1] += out[0]; state1[1] += out[1]; state2[1] += out[2]; state3[1] += out[3];
    state4[1] += out[4]; state5[1] += out[5]; state6[1] += out[6]; state7[1] += out[7];
    _mm512_storeu_si512((__m512i*)out, c);
    state0[2] += out[0]; state1[2] += out[1]; state2[2] += out[2]; state3[2] += out[3];
    state4[2] += out[4]; state5[2] += out[5]; state6[2] += out[6]; state7[2] += out[7];
    _mm512_storeu_si512((__m512i*)out, d);
    state0[3] += out[0]; state1[3] += out[1]; state2[3] += out[2]; state3[3] += out[3];
    state4[3] += out[4]; state5[3] += out[5]; state6[3] += out[6]; state7[3] += out[7];
    _mm512_storeu_si512((__m512i*)out, e);
    state0[4] += out[0]; state1[4] += out[1]; state2[4] += out[2]; state3[4] += out[3];
    state4[4] += out[4]; state5[4] += out[5]; state6[4] += out[6]; state7[4] += out[7];
    _mm512_storeu_si512((__m512i*)out, f);
    state0[5] += out[0]; state1[5] += out[1]; state2[5] += out[2]; state3[5] += out[3];
    state4[5] += out[4]; state5[5] += out[5]; state6[5] += out[6]; state7[5] += out[7];
    _mm512_storeu_si512((__m512i*)out, g);
    state0[6] += out[0]; state1[6] += out[1]; state2[6] += out[2]; state3[6] += out[3];
    state4[6] += out[4]; state5[6] += out[5]; state6[6] += out[6]; state7[6] += out[7];
    _mm512_storeu_si512((__m512i*)out, h);
    state0[7] += out[0]; state1[7] += out[1]; state2[7] += out[2]; state3[7] += out[3];
    state4[7] += out[4]; state5[7] += out[5]; state6[7] += out[6]; state7[7] += out[7];
}
#else
// When AVX-512 SHA not available, provide non-empty translation unit
typedef int sha256_avx512_not_supported;
#endif // __AVX512F__ && __SHA__
