/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file sha2_app_small_batch.c
 * @brief High-performance SHA-256 for batches of small messages using SHA-NI directly
 *
 * This example shows how to hash N messages (each length ≤55 bytes) with exactly one
 * hardware-accelerated compression per message, saturating all logical cores.
 * It bypasses the context API and directly calls the SHA-NI transform in parallel.
 *
 * Steps:
 *  1. Read or generate N random messages of msg_len bytes (≤55).
 *  2. Pad each message to a 64-byte block (0x80, zeros, 64-bit length).
 *  3. Spawn one thread per logical core.
 *  4. Each thread iterates its slice of blocks, copying the initial H0..H7,
 *     then invoking sha256_ni_transform(state, block, 1) per block.
 *  5. Measure wall-clock time around the threaded transform.
 *
 * Usage:
 *   sha2_app_small_batch <num_messages> <msg_len>
 *   - num_messages: total messages to hash
 *   - msg_len: length of each message in bytes (must be ≤55)
 */
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include "sha2.h"

// Expose the assembler SHA-NI block transform
extern void sha256_ni_transform(uint32_t *digest, const void *data, uint64_t numBlocks);

// Initial SHA-256 H0..H7 constants (big-endian)
static const uint32_t SHA256_H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/**
 * Argument structure for each worker thread.
 */
typedef struct {
    const uint8_t *blocks;  // pointer to padded 64-byte message blocks
    size_t         start;   // starting block index
    size_t         count;   // number of blocks to process
} thread_arg_t;

/**
 * Thread function: run SHA-NI on each assigned block.
 */
static void* thread_func(void *arg_) {
    thread_arg_t *arg = (thread_arg_t*)arg_;
    for (size_t i = 0; i < arg->count; i++) {
        // Local copy of initial hash state
        uint32_t state[8];
        memcpy(state, SHA256_H0, sizeof(state));
        // Perform one SHA-256 compression on block
        sha256_ni_transform(state,
                            arg->blocks + (arg->start + i) * SHA256_BLOCK_SIZE,
                            1);
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <num_messages> <msg_len (≤55)>\n", argv[0]);
        return 1;
    }
    size_t N       = strtoul(argv[1], NULL, 0);
    size_t msg_len = strtoul(argv[2], NULL, 0);
    if (msg_len > SHA256_BLOCK_SIZE - 9) {
        fprintf(stderr, "Error: msg_len must be ≤ %d\n", SHA256_BLOCK_SIZE - 9);
        return 1;
    }

    // Allocate buffers
    uint8_t *data   = malloc(N * msg_len);
    uint8_t *blocks = malloc(N * SHA256_BLOCK_SIZE);
    if (!data || !blocks) {
        perror("malloc");
        return 1;
    }

    // Fill with random data (distinct messages)
    int urfd = open("/dev/urandom", O_RDONLY);
    if (urfd >= 0) {
        size_t to_read = N * msg_len;
        size_t off = 0;
        while (off < to_read) {
            ssize_t r = read(urfd, data + off, to_read - off);
            if (r <= 0) { perror("read"); close(urfd); return 1; }
            off += (size_t)r;
        }
        close(urfd);
    } else {
        srand((unsigned)time(NULL));
        for (size_t i = 0; i < N * msg_len; i++) {
            data[i] = (uint8_t)(rand() & 0xFF);
        }
    }

    // Pad each message to 64 bytes (one compression block)
    for (size_t i = 0; i < N; i++) {
        uint8_t *dst = blocks + i * SHA256_BLOCK_SIZE;
        memcpy(dst, data + i * msg_len, msg_len);
        dst[msg_len] = 0x80;
        memset(dst + msg_len + 1, 0,
               SHA256_BLOCK_SIZE - msg_len - 1 - 8);
        uint64_t bitlen = (uint64_t)msg_len * 8;
        for (int b = 0; b < 8; b++) {
            dst[SHA256_BLOCK_SIZE - 8 + b] =
                (uint8_t)(bitlen >> (56 - 8 * b));
        }
    }

    // Prepare threading
    int nthreads = sysconf(_SC_NPROCESSORS_ONLN);
    pthread_t   *threads = malloc(sizeof(pthread_t) * nthreads);
    thread_arg_t *args   = malloc(sizeof(thread_arg_t) * nthreads);
    if (!threads || !args) {
        perror("malloc");
        return 1;
    }

    // Distribute work and time the transforms
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    size_t base = N / nthreads;
    size_t rem  = N % nthreads;
    size_t offset = 0;
    for (int t = 0; t < nthreads; t++) {
        size_t cnt = base + (t < rem ? 1 : 0);
        args[t].blocks = blocks;
        args[t].start  = offset;
        args[t].count  = cnt;
        pthread_create(&threads[t], NULL, thread_func, &args[t]);
        offset += cnt;
    }
    for (int t = 0; t < nthreads; t++) {
        pthread_join(threads[t], NULL);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);

    // Compute throughput
    double elapsed = (t1.tv_sec - t0.tv_sec) +
                     (t1.tv_nsec - t0.tv_nsec) * 1e-9;
    double mhps = N / (elapsed * 1e6);
    printf("Fast SHA-NI batch: %zu msgs of %zu bytes in %.6f s → %.3f MH/s\n",
           N, msg_len, elapsed, mhps);

    free(data);
    free(blocks);
    free(threads);
    free(args);
    return 0;
}