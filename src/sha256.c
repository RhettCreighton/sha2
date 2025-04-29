/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Rhett Creighton */

#include <stddef.h>
#include "sha2.h"
#include <stdbool.h>

/* Wrapper: dispatch to SHA-NI accelerated or scalar block processor */
#include "sha256_shaext.h"
extern void sha256_process_block_shaext(sha2_ctx *ctx, const uint8_t *block);
#include <stdbool.h>
#include <string.h>

/* SHA-256 initial hash values */
static const uint32_t SHA256_H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/* SHA-224 initial hash values */
static const uint32_t SHA224_H0[8] = {
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
};

/*
 * SHA-256 implementation based on FIPS PUB 180-4
 */

/* Scalar SHA-256 definitions (only when SHA-NI not available) */
#if !defined(__SHA__)
/* SHA-256 constants K */
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* SHA-256 initial hash values */

/* Rotate right (circular right shift) */
static inline uint32_t rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}


/* SHA-256 functions */
static inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

static inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t sigma0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

static inline uint32_t sigma1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

static inline uint32_t gamma0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

static inline uint32_t gamma1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

/* Process a single block (512 bits) of data */
/* Use runtime-dispatching wrapper for SHA-NI vs. scalar */
extern void sha256_process_block_shaext(sha2_ctx *ctx, const uint8_t *block);
void sha256_process_block(sha2_ctx *ctx, const uint8_t *block) {
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t w[64];
    uint32_t t1, t2;
    int i;

    /* Convert from big-endian to host byte order */
    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }

    /* Extend the first 16 words into the remaining 48 words */
    for (i = 16; i < 64; i++) {
        w[i] = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16];
    }

    /* Initialize working variables to current hash value */
    a = ctx->u.sha256.state[0];
    b = ctx->u.sha256.state[1];
    c = ctx->u.sha256.state[2];
    d = ctx->u.sha256.state[3];
    e = ctx->u.sha256.state[4];
    f = ctx->u.sha256.state[5];
    g = ctx->u.sha256.state[6];
    h = ctx->u.sha256.state[7];

    /* Compression function main loop (unrolled) */
    #define SHA256_ROUND(idx)                                            \
        do {                                                            \
            t1 = h + sigma1(e) + ch(e, f, g) + K[idx] + w[idx];         \
            t2 = sigma0(a) + maj(a, b, c);                              \
            h = g; g = f; f = e;                                        \
            e = d + t1;                                                 \
            d = c; c = b; b = a;                                        \
            a = t1 + t2;                                                \
        } while (0)

    SHA256_ROUND(0);  SHA256_ROUND(1);  SHA256_ROUND(2);  SHA256_ROUND(3);
    SHA256_ROUND(4);  SHA256_ROUND(5);  SHA256_ROUND(6);  SHA256_ROUND(7);
    SHA256_ROUND(8);  SHA256_ROUND(9);  SHA256_ROUND(10); SHA256_ROUND(11);
    SHA256_ROUND(12); SHA256_ROUND(13); SHA256_ROUND(14); SHA256_ROUND(15);
    SHA256_ROUND(16); SHA256_ROUND(17); SHA256_ROUND(18); SHA256_ROUND(19);
    SHA256_ROUND(20); SHA256_ROUND(21); SHA256_ROUND(22); SHA256_ROUND(23);
    SHA256_ROUND(24); SHA256_ROUND(25); SHA256_ROUND(26); SHA256_ROUND(27);
    SHA256_ROUND(28); SHA256_ROUND(29); SHA256_ROUND(30); SHA256_ROUND(31);
    SHA256_ROUND(32); SHA256_ROUND(33); SHA256_ROUND(34); SHA256_ROUND(35);
    SHA256_ROUND(36); SHA256_ROUND(37); SHA256_ROUND(38); SHA256_ROUND(39);
    SHA256_ROUND(40); SHA256_ROUND(41); SHA256_ROUND(42); SHA256_ROUND(43);
    SHA256_ROUND(44); SHA256_ROUND(45); SHA256_ROUND(46); SHA256_ROUND(47);
    SHA256_ROUND(48); SHA256_ROUND(49); SHA256_ROUND(50); SHA256_ROUND(51);
    SHA256_ROUND(52); SHA256_ROUND(53); SHA256_ROUND(54); SHA256_ROUND(55);
    SHA256_ROUND(56); SHA256_ROUND(57); SHA256_ROUND(58); SHA256_ROUND(59);
    SHA256_ROUND(60); SHA256_ROUND(61); SHA256_ROUND(62); SHA256_ROUND(63);
    #undef SHA256_ROUND

    /* Add the compressed chunk to the current hash value */
    ctx->u.sha256.state[0] += a;
    ctx->u.sha256.state[1] += b;
    ctx->u.sha256.state[2] += c;
    ctx->u.sha256.state[3] += d;
    ctx->u.sha256.state[4] += e;
    ctx->u.sha256.state[5] += f;
    ctx->u.sha256.state[6] += g;
    ctx->u.sha256.state[7] += h;
}
#endif // !__SHA__

/* Initialize SHA-256 context */
int sha256_init(void *context) {
    sha2_ctx *ctx = (sha2_ctx *)context;
    
    if (!ctx) {
        return -1;
    }
    
    /* Set initial hash values */
    memcpy(ctx->u.sha256.state, SHA256_H0, sizeof(SHA256_H0));
    
    /* Clear buffer and byte count */
    memset(ctx->u.sha256.buffer, 0, sizeof(ctx->u.sha256.buffer));
    ctx->u.sha256.total_bytes = 0;
    
    return 0;
}

/* Initialize SHA-224 context */
int sha224_init(void *context) {
    sha2_ctx *ctx = (sha2_ctx *)context;
    
    if (!ctx) {
        return -1;
    }
    
    /* Set initial hash values */
    memcpy(ctx->u.sha256.state, SHA224_H0, sizeof(SHA224_H0));
    
    /* Clear buffer and byte count */
    memset(ctx->u.sha256.buffer, 0, sizeof(ctx->u.sha256.buffer));
    ctx->u.sha256.total_bytes = 0;
    
    return 0;
}

/* Update SHA-256/SHA-224 context with more data */
int sha256_update(void *context, const void *data, size_t len) {
    sha2_ctx *ctx = (sha2_ctx *)context;
    const uint8_t *input = (const uint8_t *)data;
    size_t buffer_pos;
    
    if (!ctx || !input) {
        return -1;
    }
    
    /* Calculate current position in buffer */
    buffer_pos = (size_t)(ctx->u.sha256.total_bytes & 0x3F);
    
    /* Update total bytes processed */
    ctx->u.sha256.total_bytes += len;
    
    /* If we have data remaining from a previous update, fill the buffer */
    if (buffer_pos > 0) {
        size_t space_left = 64 - buffer_pos;
        
        /* If we don't have enough to complete a block, just copy and return */
        if (len < space_left) {
            memcpy(ctx->u.sha256.buffer + buffer_pos, input, len);
            return 0;
        }
        
        /* Fill the buffer and process it */
        memcpy(ctx->u.sha256.buffer + buffer_pos, input, space_left);
        sha256_process_block_shaext(ctx, ctx->u.sha256.buffer);
        
        /* Move to the next block of data */
        input += space_left;
        len -= space_left;
    }
    
    /* Process as many complete blocks as possible */
    while (len >= 64) {
        sha256_process_block_shaext(ctx, input);
        input += 64;
        len -= 64;
    }
    
    /* Store any remaining bytes */
    if (len > 0) {
        memcpy(ctx->u.sha256.buffer, input, len);
    }
    
    return 0;
}

/* Finalize SHA-256 and get digest */
int sha256_final(void *context, void *digest, size_t digest_size) {
    sha2_ctx *ctx = (sha2_ctx *)context;
    uint8_t *output = (uint8_t *)digest;
    uint32_t i;
    uint64_t bit_len;
    uint8_t buffer_pos;
    
    if (!ctx || !output || digest_size < SHA256_DIGEST_SIZE) {
        return -1;
    }
    
    /* Calculate current position in buffer */
    buffer_pos = (uint8_t)(ctx->u.sha256.total_bytes & 0x3F);
    
    /* Set the first char of padding to 0x80 */
    ctx->u.sha256.buffer[buffer_pos++] = 0x80;
    
    /* If there isn't enough space for the length (need 8 bytes), pad with zeros and process */
    if (buffer_pos > 56) {
        /* Pad with zeros to complete the block */
        memset(ctx->u.sha256.buffer + buffer_pos, 0, 64 - buffer_pos);
        sha256_process_block_shaext(ctx, ctx->u.sha256.buffer);
        buffer_pos = 0;
    }
    
    /* Pad with zeros up to the length field */
    memset(ctx->u.sha256.buffer + buffer_pos, 0, 56 - buffer_pos);
    
    /* Append total bit length (big-endian, 64 bits) */
    bit_len = ctx->u.sha256.total_bytes * 8;
    ctx->u.sha256.buffer[56] = (uint8_t)(bit_len >> 56);
    ctx->u.sha256.buffer[57] = (uint8_t)(bit_len >> 48);
    ctx->u.sha256.buffer[58] = (uint8_t)(bit_len >> 40);
    ctx->u.sha256.buffer[59] = (uint8_t)(bit_len >> 32);
    ctx->u.sha256.buffer[60] = (uint8_t)(bit_len >> 24);
    ctx->u.sha256.buffer[61] = (uint8_t)(bit_len >> 16);
    ctx->u.sha256.buffer[62] = (uint8_t)(bit_len >> 8);
    ctx->u.sha256.buffer[63] = (uint8_t)bit_len;
    
    /* Process the final block */
    sha256_process_block_shaext(ctx, ctx->u.sha256.buffer);
    
    /* Copy the hash value to the output buffer (big-endian) */
    for (i = 0; i < 8; i++) {
        output[i * 4] = (uint8_t)(ctx->u.sha256.state[i] >> 24);
        output[i * 4 + 1] = (uint8_t)(ctx->u.sha256.state[i] >> 16);
        output[i * 4 + 2] = (uint8_t)(ctx->u.sha256.state[i] >> 8);
        output[i * 4 + 3] = (uint8_t)(ctx->u.sha256.state[i]);
    }
    
    /* Clear sensitive data */
    memset(ctx->u.sha256.buffer, 0, sizeof(ctx->u.sha256.buffer));
    
    return SHA256_DIGEST_SIZE;
}

/* Finalize SHA-224 and get digest */
int sha224_final(void *context, void *digest, size_t digest_size) {
    sha2_ctx *ctx = (sha2_ctx *)context;
    uint8_t full_digest[SHA256_DIGEST_SIZE];
    
    if (!ctx || !digest || digest_size < SHA224_DIGEST_SIZE) {
        return -1;
    }
    
    /* Use the SHA-256 finalization and then truncate the result */
    if (sha256_final(ctx, full_digest, SHA256_DIGEST_SIZE) != SHA256_DIGEST_SIZE) {
        return -1;
    }
    
    /* Copy only the first 28 bytes (224 bits) */
    memcpy(digest, full_digest, SHA224_DIGEST_SIZE);
    
    return SHA224_DIGEST_SIZE;
}
