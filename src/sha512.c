#ifndef SHA512_LICENSE
/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Rhett Creighton */
#define SHA512_LICENSE
#endif
#include "sha2.h"
#include <string.h>
#include <immintrin.h>

/*
 * SHA-512 implementation based on FIPS PUB 180-4
 */

/* SHA-512 constants K */
static const uint64_t K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

/* SHA-512 initial hash values */
static const uint64_t SHA512_H0[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

/* SHA-384 initial hash values */
static const uint64_t SHA384_H0[8] = {
    0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
    0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL, 0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL
};

/* Rotate right (circular right shift) */
static inline uint64_t rotr64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}




/* SHA-512 functions */
static inline uint64_t ch(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ (~x & z);
}

static inline uint64_t maj(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint64_t sigma0(uint64_t x) {
    return rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39);
}

static inline uint64_t sigma1(uint64_t x) {
    return rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41);
}

static inline uint64_t gamma0(uint64_t x) {
    return rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7);
}

static inline uint64_t gamma1(uint64_t x) {
    return rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6);
}

/* Process a single block (1024 bits) of data */
void sha512_process_block(sha2_ctx *ctx, const uint8_t *block) {
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t w[80];
    uint64_t t1, t2;
    int i;

    /* Convert from big-endian to host byte order */
    for (i = 0; i < 16; i++) {
        w[i] = ((uint64_t)block[i * 8] << 56) |
               ((uint64_t)block[i * 8 + 1] << 48) |
               ((uint64_t)block[i * 8 + 2] << 40) |
               ((uint64_t)block[i * 8 + 3] << 32) |
               ((uint64_t)block[i * 8 + 4] << 24) |
               ((uint64_t)block[i * 8 + 5] << 16) |
               ((uint64_t)block[i * 8 + 6] << 8) |
               ((uint64_t)block[i * 8 + 7]);
    }

    /* Extend the first 16 words into the remaining 64 words */
    for (i = 16; i < 80; i++) {
        w[i] = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16];
    }

    /* Initialize working variables to current hash value */
    a = ctx->u.sha512.state[0];
    b = ctx->u.sha512.state[1];
    c = ctx->u.sha512.state[2];
    d = ctx->u.sha512.state[3];
    e = ctx->u.sha512.state[4];
    f = ctx->u.sha512.state[5];
    g = ctx->u.sha512.state[6];
    h = ctx->u.sha512.state[7];

    /* Compression function main loop */
    for (i = 0; i < 80; i++) {
        t1 = h + sigma1(e) + ch(e, f, g) + K[i] + w[i];
        t2 = sigma0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    /* Add the compressed chunk to the current hash value */
    ctx->u.sha512.state[0] += a;
    ctx->u.sha512.state[1] += b;
    ctx->u.sha512.state[2] += c;
    ctx->u.sha512.state[3] += d;
    ctx->u.sha512.state[4] += e;
    ctx->u.sha512.state[5] += f;
    ctx->u.sha512.state[6] += g;
    ctx->u.sha512.state[7] += h;
}

/* Initialize SHA-512 context */
int sha512_init(void *context) {
    sha2_ctx *ctx = (sha2_ctx *)context;
    
    if (!ctx) {
        return -1;
    }
    
    /* Set initial hash values */
    memcpy(ctx->u.sha512.state, SHA512_H0, sizeof(SHA512_H0));
    
    /* Clear buffer and byte count */
    memset(ctx->u.sha512.buffer, 0, sizeof(ctx->u.sha512.buffer));
    ctx->u.sha512.total_bytes[0] = 0;
    ctx->u.sha512.total_bytes[1] = 0;
    
    return 0;
}

/* Initialize SHA-384 context */
int sha384_init(void *context) {
    sha2_ctx *ctx = (sha2_ctx *)context;
    
    if (!ctx) {
        return -1;
    }
    
    /* Set initial hash values */
    memcpy(ctx->u.sha512.state, SHA384_H0, sizeof(SHA384_H0));
    
    /* Clear buffer and byte count */
    memset(ctx->u.sha512.buffer, 0, sizeof(ctx->u.sha512.buffer));
    ctx->u.sha512.total_bytes[0] = 0;
    ctx->u.sha512.total_bytes[1] = 0;
    
    return 0;
}

/* Update SHA-512/SHA-384 context with more data */
int sha512_update(void *context, const void *data, size_t len) {
    sha2_ctx *ctx = (sha2_ctx *)context;
    const uint8_t *input = (const uint8_t *)data;
    size_t buffer_pos;
    
    if (!ctx || !input) {
        return -1;
    }
    
    /* Calculate current position in buffer */
    buffer_pos = (size_t)(ctx->u.sha512.total_bytes[0] & 0x7F);
    
    /* Update total bytes processed (128-bit counter) */
    if (ctx->u.sha512.total_bytes[0] + len < ctx->u.sha512.total_bytes[0]) {
        ctx->u.sha512.total_bytes[1]++;  /* Handle overflow */
    }
    ctx->u.sha512.total_bytes[0] += len;
    
    /* If we have data remaining from a previous update, fill the buffer */
    if (buffer_pos > 0) {
        size_t space_left = 128 - buffer_pos;
        
        /* If we don't have enough to complete a block, just copy and return */
        if (len < space_left) {
            memcpy(ctx->u.sha512.buffer + buffer_pos, input, len);
            return 0;
        }
        
        /* Fill the buffer and process it */
        memcpy(ctx->u.sha512.buffer + buffer_pos, input, space_left);
        sha512_process_block(ctx, ctx->u.sha512.buffer);
        
        /* Move to the next block of data */
        input += space_left;
        len -= space_left;
    }
    
    /* Process as many complete blocks as possible */
    // AVX-512 8-way path
#ifdef __AVX512F__
    if (__builtin_cpu_supports("avx512f")) {
        while (len >= 128 * 8) {
            /* Prefetch next 8-block batch */
            _mm_prefetch((const char *)input + 128 * 8, _MM_HINT_T0);
            sha512_process8_avx512(
                ctx->u.sha512.state, ctx->u.sha512.state, ctx->u.sha512.state, ctx->u.sha512.state,
                ctx->u.sha512.state, ctx->u.sha512.state, ctx->u.sha512.state, ctx->u.sha512.state,
                input, input + 128, input + 256, input + 384,
                input + 512, input + 640, input + 768, input + 896
            );
            input += 128 * 8;
            len -= 128 * 8;
        }
    }
#endif
    // AVX2 4-way path
#ifdef __AVX2__
    if (__builtin_cpu_supports("avx2")) {
        while (len >= 128 * 4) {
            /* Prefetch next 4-block batch */
            _mm_prefetch((const char *)input + 128 * 4, _MM_HINT_T0);
            sha512_process4_avx2(
                ctx->u.sha512.state, ctx->u.sha512.state, ctx->u.sha512.state, ctx->u.sha512.state,
                input, input + 128, input + 256, input + 384
            );
            input += 128 * 4;
            len -= 128 * 4;
        }
    }
#endif
    // Scalar fallback
    while (len >= 128) {
        sha512_process_block(ctx, input);
        input += 128;
        len -= 128;
    }
    
    /* Store any remaining bytes */
    if (len > 0) {
        memcpy(ctx->u.sha512.buffer, input, len);
    }
    
    return 0;
}

/* Finalize SHA-512 and get digest */
int sha512_final(void *context, void *digest, size_t digest_size) {
    sha2_ctx *ctx = (sha2_ctx *)context;
    uint8_t *output = (uint8_t *)digest;
    uint32_t i;
    uint8_t buffer_pos;
    uint64_t bit_len_high, bit_len_low;
    
    if (!ctx || !output || digest_size < SHA512_DIGEST_SIZE) {
        return -1;
    }
    
    /* Calculate current position in buffer */
    buffer_pos = (uint8_t)(ctx->u.sha512.total_bytes[0] & 0x7F);
    
    /* Set the first char of padding to 0x80 */
    ctx->u.sha512.buffer[buffer_pos++] = 0x80;
    
    /* If there isn't enough space for the length (need 16 bytes), pad with zeros and process */
    if (buffer_pos > 112) {
        /* Pad with zeros to complete the block */
        memset(ctx->u.sha512.buffer + buffer_pos, 0, 128 - buffer_pos);
        sha512_process_block(ctx, ctx->u.sha512.buffer);
        buffer_pos = 0;
    }
    
    /* Pad with zeros up to the length field */
    memset(ctx->u.sha512.buffer + buffer_pos, 0, 112 - buffer_pos);
    
    /* Append total bit length (big-endian, 128 bits) */
    bit_len_high = (ctx->u.sha512.total_bytes[1] << 3) | (ctx->u.sha512.total_bytes[0] >> 61);
    bit_len_low = ctx->u.sha512.total_bytes[0] << 3;
    
    ctx->u.sha512.buffer[112] = (uint8_t)(bit_len_high >> 56);
    ctx->u.sha512.buffer[113] = (uint8_t)(bit_len_high >> 48);
    ctx->u.sha512.buffer[114] = (uint8_t)(bit_len_high >> 40);
    ctx->u.sha512.buffer[115] = (uint8_t)(bit_len_high >> 32);
    ctx->u.sha512.buffer[116] = (uint8_t)(bit_len_high >> 24);
    ctx->u.sha512.buffer[117] = (uint8_t)(bit_len_high >> 16);
    ctx->u.sha512.buffer[118] = (uint8_t)(bit_len_high >> 8);
    ctx->u.sha512.buffer[119] = (uint8_t)bit_len_high;
    
    ctx->u.sha512.buffer[120] = (uint8_t)(bit_len_low >> 56);
    ctx->u.sha512.buffer[121] = (uint8_t)(bit_len_low >> 48);
    ctx->u.sha512.buffer[122] = (uint8_t)(bit_len_low >> 40);
    ctx->u.sha512.buffer[123] = (uint8_t)(bit_len_low >> 32);
    ctx->u.sha512.buffer[124] = (uint8_t)(bit_len_low >> 24);
    ctx->u.sha512.buffer[125] = (uint8_t)(bit_len_low >> 16);
    ctx->u.sha512.buffer[126] = (uint8_t)(bit_len_low >> 8);
    ctx->u.sha512.buffer[127] = (uint8_t)bit_len_low;
    
    /* Process the final block */
    sha512_process_block(ctx, ctx->u.sha512.buffer);
    
    /* Copy the hash value to the output buffer (big-endian) */
    for (i = 0; i < 8; i++) {
        output[i * 8] = (uint8_t)(ctx->u.sha512.state[i] >> 56);
        output[i * 8 + 1] = (uint8_t)(ctx->u.sha512.state[i] >> 48);
        output[i * 8 + 2] = (uint8_t)(ctx->u.sha512.state[i] >> 40);
        output[i * 8 + 3] = (uint8_t)(ctx->u.sha512.state[i] >> 32);
        output[i * 8 + 4] = (uint8_t)(ctx->u.sha512.state[i] >> 24);
        output[i * 8 + 5] = (uint8_t)(ctx->u.sha512.state[i] >> 16);
        output[i * 8 + 6] = (uint8_t)(ctx->u.sha512.state[i] >> 8);
        output[i * 8 + 7] = (uint8_t)(ctx->u.sha512.state[i]);
    }
    
    /* Clear sensitive data */
    memset(ctx->u.sha512.buffer, 0, sizeof(ctx->u.sha512.buffer));
    
    return SHA512_DIGEST_SIZE;
}

/* Finalize SHA-384 and get digest */
int sha384_final(void *context, void *digest, size_t digest_size) {
    sha2_ctx *ctx = (sha2_ctx *)context;
    uint8_t full_digest[SHA512_DIGEST_SIZE];
    
    if (!ctx || !digest || digest_size < SHA384_DIGEST_SIZE) {
        return -1;
    }
    
    /* Use the SHA-512 finalization and then truncate the result */
    if (sha512_final(ctx, full_digest, SHA512_DIGEST_SIZE) != SHA512_DIGEST_SIZE) {
        return -1;
    }
    
    /* Copy only the first 48 bytes (384 bits) */
    memcpy(digest, full_digest, SHA384_DIGEST_SIZE);
    
    return SHA384_DIGEST_SIZE;
}
