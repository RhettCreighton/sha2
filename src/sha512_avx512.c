/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Rhett Creighton */

/*
 * sha512_avx512.c
 *
 * AVX-512 vectorized implementation of SHA-512 (8-way parallel)
 */
#if defined(__AVX512F__)
#include "sha2.h"
#include <immintrin.h>
#include <string.h>

// Rotate right 64-bit lanes in 512-bit vector
static inline __m512i rotr64_8(__m512i x, int r) {
    return _mm512_or_si512(_mm512_srli_epi64(x, r),
                           _mm512_slli_epi64(x, 64 - r));
}

// SHA-512 big sigma functions
static inline __m512i Sigma0_8(__m512i x) {
    return _mm512_xor_epi64(_mm512_xor_epi64(rotr64_8(x, 28),
                                             rotr64_8(x, 34)),
                             rotr64_8(x, 39));
}
static inline __m512i Sigma1_8(__m512i x) {
    return _mm512_xor_epi64(_mm512_xor_epi64(rotr64_8(x, 14),
                                             rotr64_8(x, 18)),
                             rotr64_8(x, 41));
}

// SHA-512 small sigma (message schedule)
static inline __m512i gamma0_8(__m512i x) {
    return _mm512_xor_epi64(_mm512_xor_epi64(rotr64_8(x, 1),
                                             rotr64_8(x, 8)),
                             _mm512_srli_epi64(x, 7));
}
static inline __m512i gamma1_8(__m512i x) {
    return _mm512_xor_epi64(_mm512_xor_epi64(rotr64_8(x, 19),
                                             rotr64_8(x, 61)),
                             _mm512_srli_epi64(x, 6));
}

// SHA-512 choice and majority
static inline __m512i ch_8(__m512i x, __m512i y, __m512i z) {
    return _mm512_xor_epi64(_mm512_and_epi64(x, y),
                             _mm512_andnot_epi64(x, z));
}
static inline __m512i maj_8(__m512i x, __m512i y, __m512i z) {
    __m512i t1 = _mm512_and_epi64(x, y);
    __m512i t2 = _mm512_and_epi64(x, z);
    __m512i t3 = _mm512_and_epi64(y, z);
    return _mm512_xor_epi64(_mm512_xor_epi64(t1, t2), t3);
}

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

/**
 * @brief Process eight independent 1024-bit blocks in parallel using AVX-512
 * @param state0..7 Eight 8-word state arrays (a-h) to update
 * @param block0..7 Eight pointers to 128-byte input blocks
 */
void sha512_process8_avx512(
    uint64_t state0[8], uint64_t state1[8], uint64_t state2[8], uint64_t state3[8],
    uint64_t state4[8], uint64_t state5[8], uint64_t state6[8], uint64_t state7[8],
    const uint8_t *block0, const uint8_t *block1, const uint8_t *block2, const uint8_t *block3,
    const uint8_t *block4, const uint8_t *block5, const uint8_t *block6, const uint8_t *block7
) {
    __m512i W[80];
    // Initialize working vars a-h across lanes 0..7
    __m512i a = _mm512_setr_epi64(state0[0], state1[0], state2[0], state3[0],
                                   state4[0], state5[0], state6[0], state7[0]);
    __m512i b = _mm512_setr_epi64(state0[1], state1[1], state2[1], state3[1],
                                   state4[1], state5[1], state6[1], state7[1]);
    __m512i c = _mm512_setr_epi64(state0[2], state1[2], state2[2], state3[2],
                                   state4[2], state5[2], state6[2], state7[2]);
    __m512i d = _mm512_setr_epi64(state0[3], state1[3], state2[3], state3[3],
                                   state4[3], state5[3], state6[3], state7[3]);
    __m512i e = _mm512_setr_epi64(state0[4], state1[4], state2[4], state3[4],
                                   state4[4], state5[4], state6[4], state7[4]);
    __m512i f = _mm512_setr_epi64(state0[5], state1[5], state2[5], state3[5],
                                   state4[5], state5[5], state6[5], state7[5]);
    __m512i g = _mm512_setr_epi64(state0[6], state1[6], state2[6], state3[6],
                                   state4[6], state5[6], state6[6], state7[6]);
    __m512i h = _mm512_setr_epi64(state0[7], state1[7], state2[7], state3[7],
                                   state4[7], state5[7], state6[7], state7[7]);

    // Load message blocks (big-endian) into W[0..15]
    for (int i = 0; i < 16; i++) {
        uint64_t w0, w1, w2, w3, w4, w5, w6, w7;
        memcpy(&w0, block0 + i*8, 8); w0 = __builtin_bswap64(w0);
        memcpy(&w1, block1 + i*8, 8); w1 = __builtin_bswap64(w1);
        memcpy(&w2, block2 + i*8, 8); w2 = __builtin_bswap64(w2);
        memcpy(&w3, block3 + i*8, 8); w3 = __builtin_bswap64(w3);
        memcpy(&w4, block4 + i*8, 8); w4 = __builtin_bswap64(w4);
        memcpy(&w5, block5 + i*8, 8); w5 = __builtin_bswap64(w5);
        memcpy(&w6, block6 + i*8, 8); w6 = __builtin_bswap64(w6);
        memcpy(&w7, block7 + i*8, 8); w7 = __builtin_bswap64(w7);
        W[i] = _mm512_setr_epi64(w0, w1, w2, w3, w4, w5, w6, w7);
    }

    // Message schedule W[16..79]
    for (int i = 16; i < 80; i++) {
        __m512i s1 = gamma1_8(W[i-2]);
        __m512i s0 = gamma0_8(W[i-15]);
        W[i] = _mm512_add_epi64(
                    _mm512_add_epi64(_mm512_add_epi64(s1, W[i-7]), s0),
                    W[i-16]
                );
    }

    // Compression rounds
    for (int i = 0; i < 80; i++) {
        __m512i T1 = _mm512_add_epi64(
            _mm512_add_epi64(_mm512_add_epi64(h, Sigma1_8(e)), ch_8(e,f,g)),
            _mm512_add_epi64(_mm512_set1_epi64(K512[i]), W[i])
        );
        __m512i T2 = _mm512_add_epi64(Sigma0_8(a), maj_8(a,b,c));
        h = g; g = f; f = e;
        e = _mm512_add_epi64(d, T1);
        d = c; c = b; b = a;
        a = _mm512_add_epi64(T1, T2);
    }

    // Add back to state arrays
    uint64_t out[8];
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
// When AVX-512 not available, provide non-empty translation unit
typedef int sha512_avx512_not_supported;
#endif // __AVX512F__
