/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Rhett Creighton */

/*
 * sha2_parallel.c
 *
 * Parallel SHA-256 hashing API.
 */
#define _POSIX_C_SOURCE 200809L
#include "sha2.h"
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
// Expose SHA-NI block transform (defined in sha256_ni_transform.S)
extern void sha256_ni_transform(uint32_t *digest, const void *data, uint64_t numBlocks);

// Initial SHA-256 hash values
static const uint32_t SHA256_H0_CONST[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/**
 * Thread argument for direct SHA-NI single-block path
 */
typedef struct {
    const uint8_t *blocks;  // pointer to padded 64-byte blocks
    uint8_t       *digests; // pointer to output digests buffer
    size_t         start;   // starting block index
    size_t         count;   // number of blocks to process
} ni_thread_arg_t;

/**
 * Thread function: perform SHA-NI on each block and write digest
 */
static void* sha256_many_ni_thread(void *arg_) {
    ni_thread_arg_t *arg = (ni_thread_arg_t*)arg_;
    for (size_t i = 0; i < arg->count; i++) {
        uint32_t state[8];
        memcpy(state, SHA256_H0_CONST, sizeof(state));
        const uint8_t *blk = arg->blocks + (arg->start + i) * SHA256_BLOCK_SIZE;
        sha256_ni_transform(state, blk, 1);
        uint8_t *out = arg->digests + (arg->start + i) * SHA256_DIGEST_SIZE;
        for (int j = 0; j < 8; j++) {
            out[j*4 + 0] = (uint8_t)(state[j] >> 24);
            out[j*4 + 1] = (uint8_t)(state[j] >> 16);
            out[j*4 + 2] = (uint8_t)(state[j] >> 8);
            out[j*4 + 3] = (uint8_t)(state[j]      );
        }
    }
    return NULL;
}

/**
 * Fast path: batch SHA-256 on single 64-byte blocks using SHA-NI
 * Data must be padded blocks (n × 64 bytes).
 */
static int sha256_hash_many_ni(const void *blocks_, void *digests_, size_t n) {
    if (!blocks_ || !digests_) return -1;
    const uint8_t *blocks = (const uint8_t*)blocks_;
    uint8_t *digests = (uint8_t*)digests_;
    size_t nthreads = sysconf(_SC_NPROCESSORS_ONLN);
    if (nthreads < 1) nthreads = 1;
    if (nthreads > n) nthreads = n;
    pthread_t *threads = malloc(sizeof(pthread_t) * nthreads);
    ni_thread_arg_t *args = malloc(sizeof(ni_thread_arg_t) * nthreads);
    if (!threads || !args) {
        free(threads);
        free(args);
        return -1;
    }
    size_t base = n / nthreads;
    size_t rem  = n % nthreads;
    size_t offset = 0;
    for (size_t t = 0; t < nthreads; t++) {
        size_t cnt = base + (t < rem ? 1 : 0);
        args[t].blocks  = blocks;
        args[t].digests = digests;
        args[t].start   = offset;
        args[t].count   = cnt;
        pthread_create(&threads[t], NULL, sha256_many_ni_thread, &args[t]);
        offset += cnt;
    }
    for (size_t t = 0; t < nthreads; t++) {
        pthread_join(threads[t], NULL);
    }
    free(threads);
    free(args);
    return 0;
}

/* Thread argument for parallel hashing */
typedef struct {
    sha2_hash_type type;
    const uint8_t *data;
    uint8_t *digests;
    size_t start;   /* message index start */
    size_t count;   /* number of messages */
} thread_arg_t;

/* Thread function: compute sha2_hash for each assigned block */
static void* sha2_parallel_thread(void *arg_) {
    thread_arg_t *arg = (thread_arg_t*)arg_;
    size_t idx = arg->start;
    const uint8_t *in = arg->data + idx * SHA256_BLOCK_SIZE;
    uint8_t *out = arg->digests + idx * SHA256_DIGEST_SIZE;
    for (size_t i = 0; i < arg->count; i++) {
        sha2_hash(arg->type,
                  in + i * SHA256_BLOCK_SIZE,
                  SHA256_BLOCK_SIZE,
                  out + i * SHA256_DIGEST_SIZE,
                  SHA256_DIGEST_SIZE);
    }
    return NULL;
}

int sha2_hash_parallel(sha2_hash_type type,
                       const void *data,
                       void *digests,
                       size_t n) {
    if (type != SHA2_256 || !data || !digests)
        return -1;
    size_t nthreads = sysconf(_SC_NPROCESSORS_ONLN);
    if (nthreads < 1)
        nthreads = 1;
    if (nthreads > n)
        nthreads = n;
    pthread_t *threads = malloc(sizeof(pthread_t) * nthreads);
    thread_arg_t *args = malloc(sizeof(thread_arg_t) * nthreads);
    if (!threads || !args) {
        free(threads);
        free(args);
        return -1;
    }
    /* divide work evenly */
    size_t base = n / nthreads;
    size_t rem = n % nthreads;
    size_t offset = 0;
    for (size_t t = 0; t < nthreads; t++) {
        size_t cnt = base + (t < rem ? 1 : 0);
        args[t].type = type;
        args[t].data = (const uint8_t*)data;
        args[t].digests = (uint8_t*)digests;
        args[t].start = offset;
        args[t].count = cnt;
        pthread_create(&threads[t], NULL,
                       sha2_parallel_thread, &args[t]);
        offset += cnt;
    }
    /* join threads */
    for (size_t t = 0; t < nthreads; t++) {
        pthread_join(threads[t], NULL);
    }
    free(threads);
    free(args);
    return 0;
}
/**
 * Public API: compute N SHA-256 hashes of uniform-length messages with maximal parallelism.
 */
int sha2_hash_many(sha2_hash_type type,
                   const void *data,
                   size_t msg_len,
                   void *digests,
                   size_t n) {
    if (type != SHA2_256 || !data || !digests)
        return -1;
    if (n == 0)
        return 0;
    /* Case 1: messages already full blocks */
    if (msg_len == SHA256_BLOCK_SIZE) {
        return sha2_hash_parallel(type, data, digests, n);
    }
    /* Case 2: short messages fitting in one block with padding */
    if (msg_len <= SHA256_BLOCK_SIZE - 9) {
        /*
         * Single-block padding path: pad each message to 64 bytes
         * then dispatch to the fastest per-block SHA-256 transform.
         */
        size_t block_size = SHA256_BLOCK_SIZE;
        size_t total = n * block_size;
        uint8_t *blocks = malloc(total);
        if (!blocks)
            return -1;
        const uint8_t *in = (const uint8_t*)data;
        for (size_t i = 0; i < n; i++) {
            uint8_t *blk = blocks + i * block_size;
            memcpy(blk, in + i * msg_len, msg_len);
            blk[msg_len] = 0x80;
            size_t pad_zero = block_size - msg_len - 1 - 8;
            memset(blk + msg_len + 1, 0, pad_zero);
            uint64_t bitlen = (uint64_t)msg_len * 8;
            for (int b = 0; b < 8; b++) {
                blk[block_size - 8 + b] = (uint8_t)(bitlen >> (56 - 8 * b));
            }
        }
        /* If SHA-NI is available, use direct multi-threaded SHA-NI path */
#if defined(__SHA__)
        if (type == SHA2_256) {
            int ret = sha256_hash_many_ni(blocks, digests, n);
            free(blocks);
            return ret;
        }
#endif
        /* Fallback: thread-based hash via generic path */
        int ret = sha2_hash_parallel(type, blocks, digests, n);
        free(blocks);
        return ret;
    }
    /* Fallback: serial per-message hashing */
    const uint8_t *in = (const uint8_t*)data;
    uint8_t *out = (uint8_t*)digests;
    for (size_t i = 0; i < n; i++) {
        sha2_hash(type,
                  in + i * msg_len,
                  msg_len,
                  out + i * SHA256_DIGEST_SIZE,
                  SHA256_DIGEST_SIZE);
    }
    return 0;
}
