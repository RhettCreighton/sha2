/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file sha2_app_fast_api.c
 * @brief Friendly example: use sha256_hash_many API for peak small-message throughput
 *
 * Demonstrates how application code can simply call the public API
 * sha256_hash_many() on batches of small messages (≤55 bytes) and
 * automatically benefit from the SHA-NI fast path with multi-threading.
 *
 * Steps:
 *   1. Allocate N messages and N*32-byte digest buffer.
 *   2. Fill the message buffer with random data.
 *   3. Call sha256_hash_many(messages, msg_len, digests, N).
 *   4. Measure elapsed time and report MH/s.
 *
 * Usage:
 *   sha2_app_fast_api <num_messages> <msg_len>
 *   - num_messages: total messages to hash
 *   - msg_len: length of each message in bytes (must be ≤55)
 */
#define _POSIX_C_SOURCE 200809L
#include <sha2.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <num_messages> <msg_len (≤55)>\n", argv[0]);
        return 1;
    }
    size_t N = strtoul(argv[1], NULL, 0);
    size_t msg_len = strtoul(argv[2], NULL, 0);
    if (msg_len > SHA256_BLOCK_SIZE - 9) {
        fprintf(stderr, "Error: msg_len must be ≤ %d\n", SHA256_BLOCK_SIZE - 9);
        return 1;
    }

    // Allocate buffers
    uint8_t *messages = malloc(N * msg_len);
    uint8_t *digests  = malloc(N * SHA256_DIGEST_SIZE);
    if (!messages || !digests) {
        perror("malloc");
        free(messages);
        free(digests);
        return 1;
    }

    // Fill messages with random bytes
    int urfd = open("/dev/urandom", O_RDONLY);
    if (urfd >= 0) {
        size_t total = N * msg_len;
        size_t off = 0;
        while (off < total) {
            ssize_t r = read(urfd, messages + off, total - off);
            if (r <= 0) { perror("read"); close(urfd); return 1; }
            off += (size_t)r;
        }
        close(urfd);
    } else {
        srand((unsigned)time(NULL));
        for (size_t i = 0; i < N * msg_len; i++) {
            messages[i] = (uint8_t)(rand() & 0xFF);
        }
    }

    // Hash all messages in one call
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (sha256_hash_many(messages, msg_len, digests, N) != 0) {
        fprintf(stderr, "sha256_hash_many failed\n");
        free(messages);
        free(digests);
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);

    double elapsed = (t1.tv_sec - t0.tv_sec) +
                     (t1.tv_nsec - t0.tv_nsec) * 1e-9;
    double mhps = N / (elapsed * 1e6);
    printf("API SHA-256: hashed %zu msgs of %zu bytes in %.6f s → %.3f MH/s\n",
           N, msg_len, elapsed, mhps);

    free(messages);
    free(digests);
    return 0;
}