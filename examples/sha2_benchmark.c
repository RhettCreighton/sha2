/**
 * @file sha2_benchmark.c
 * @brief Benchmark example: measure SHA-256 hashes per second
 */
#ifndef BENCH_SHA256_LICENSE
/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Rhett Creighton */
#define BENCH_SHA256_LICENSE
#endif
#define _POSIX_C_SOURCE 199309L
#include "sha2.h"
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// Inline RDTSC reader
static inline uint64_t rdtsc(void) {
    unsigned int lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

// High-resolution timestamp (seconds)
static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

int main(void) {
    const size_t sizes[] = { 64, 1024, 4096, 1048576 };
    const int num_sizes = sizeof(sizes) / sizeof(sizes[0]);
    uint8_t *buffer = malloc(sizes[num_sizes - 1]);
    uint8_t digest[SHA2_MAX_DIGEST_SIZE];
    if (!buffer) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return 1;
    }
    // Initialize buffer with a repeating pattern
    for (size_t i = 0; i < sizes[num_sizes - 1]; i++) {
        buffer[i] = (uint8_t)(i & 0xFF);
    }

    printf("SHA-256 Benchmark (time + cycles)\n");
    printf("Block sizes: 64 B, 1 KB, 4 KB, 1 MB\n");
    const double TIME_SEC = 1.0;

    for (int idx = 0; idx < num_sizes; idx++) {
        size_t blk = sizes[idx];
        // Warm-up
        for (int i = 0; i < 10; i++) {
            sha2_hash(SHA2_256, buffer, blk, digest, SHA256_DIGEST_SIZE);
        }
        // Time-based measurement
        double t_start = now();
        unsigned long long count = 0;
        while (now() - t_start < TIME_SEC) {
            sha2_hash(SHA2_256, buffer, blk, digest, SHA256_DIGEST_SIZE);
            count++;
        }
        double t_end = now();
        double elapsed = t_end - t_start;
        // Cycle-based measurement
        uint64_t c_start = rdtsc();
        for (unsigned long long i = 0; i < count; i++) {
            sha2_hash(SHA2_256, buffer, blk, digest, SHA256_DIGEST_SIZE);
        }
        uint64_t c_end = rdtsc();
        uint64_t cycles = c_end - c_start;

        printf("\n[%6zu bytes] iterations: %10llu, time: %.6f s, hashes/s: %.2f\n",
               blk, count, elapsed, count / elapsed);
        printf("           cycles: %12llu, cycles/hash: %8.2f, cycles/byte: %.4f\n",
               (unsigned long long)cycles,
               (double)cycles / count,
               (double)cycles / (count * blk));
#ifdef __AVX2__
        if (blk == 64) {
            // AVX2 4-way parallel benchmark
            sha2_ctx ctx0, ctx1, ctx2, ctx3;
            sha2_init(&ctx0, SHA2_256);
            sha2_init(&ctx1, SHA2_256);
            sha2_init(&ctx2, SHA2_256);
            sha2_init(&ctx3, SHA2_256);
            uint32_t st0[8], st1[8], st2[8], st3[8];
            memcpy(st0, ctx0.u.sha256.state, sizeof(st0));
            memcpy(st1, ctx1.u.sha256.state, sizeof(st1));
            memcpy(st2, ctx2.u.sha256.state, sizeof(st2));
            memcpy(st3, ctx3.u.sha256.state, sizeof(st3));
            // Warm-up
            for (int i = 0; i < 10; i++) {
                sha256_process4_avx2(st0, st1, st2, st3, buffer, buffer, buffer, buffer);
            }
            // Time-based measurement
            double t4_start = now();
            unsigned long long count4 = 0;
            while (now() - t4_start < TIME_SEC) {
                sha256_process4_avx2(st0, st1, st2, st3, buffer, buffer, buffer, buffer);
                count4++;
            }
            double elapsed4 = now() - t4_start;
            // Cycle-based measurement
            uint64_t c4_start = rdtsc();
            for (unsigned long long i = 0; i < count4; i++) {
                sha256_process4_avx2(st0, st1, st2, st3, buffer, buffer, buffer, buffer);
            }
            uint64_t c4_end = rdtsc();
            uint64_t cycles4 = c4_end - c4_start;
            unsigned long long hashes4 = count4 * 4ULL;
            printf("    AVX2-4way: iterations: %10llu, time: %.6f s, hashes/s: %.2f\n",
                   hashes4, elapsed4, hashes4 / elapsed4);
            printf("               cycles: %12llu, cycles/hash: %8.2f, cycles/byte: %.4f\n",
                   (unsigned long long)cycles4,
                   (double)cycles4 / hashes4,
                   (double)cycles4 / (hashes4 * blk));
        }
#endif
    // AVX-512 8-way parallel benchmark
#if defined(__AVX512F__) && defined(__SHA__)
        if (blk == 64) {
            // Prepare eight contexts
            sha2_ctx ctx0, ctx1, ctx2, ctx3, ctx4, ctx5, ctx6, ctx7;
            sha2_init(&ctx0, SHA2_256);
            sha2_init(&ctx1, SHA2_256);
            sha2_init(&ctx2, SHA2_256);
            sha2_init(&ctx3, SHA2_256);
            sha2_init(&ctx4, SHA2_256);
            sha2_init(&ctx5, SHA2_256);
            sha2_init(&ctx6, SHA2_256);
            sha2_init(&ctx7, SHA2_256);
            uint32_t st0[8], st1[8], st2[8], st3[8], st4[8], st5[8], st6[8], st7[8];
            memcpy(st0, ctx0.u.sha256.state, sizeof(st0));
            memcpy(st1, ctx1.u.sha256.state, sizeof(st1));
            memcpy(st2, ctx2.u.sha256.state, sizeof(st2));
            memcpy(st3, ctx3.u.sha256.state, sizeof(st3));
            memcpy(st4, ctx4.u.sha256.state, sizeof(st4));
            memcpy(st5, ctx5.u.sha256.state, sizeof(st5));
            memcpy(st6, ctx6.u.sha256.state, sizeof(st6));
            memcpy(st7, ctx7.u.sha256.state, sizeof(st7));
            // Warm-up
            for (int i = 0; i < 10; i++) {
                sha256_process8_avx512(st0,st1,st2,st3,st4,st5,st6,st7,
                                       buffer,buffer,buffer,buffer,buffer,buffer,buffer,buffer);
            }
            // Time-based measurement
            double t8_start = now();
            unsigned long long count8 = 0;
            while (now() - t8_start < TIME_SEC) {
                sha256_process8_avx512(st0,st1,st2,st3,st4,st5,st6,st7,
                                       buffer,buffer,buffer,buffer,buffer,buffer,buffer,buffer);
                count8++;
            }
            double elapsed8 = now() - t8_start;
            // Cycle-based measurement
            uint64_t c8_start = rdtsc();
            for (unsigned long long i = 0; i < count8; i++) {
                sha256_process8_avx512(st0,st1,st2,st3,st4,st5,st6,st7,
                                       buffer,buffer,buffer,buffer,buffer,buffer,buffer,buffer);
            }
            uint64_t c8_end = rdtsc();
            uint64_t cycles8 = c8_end - c8_start;
            unsigned long long hashes8 = count8 * 8ULL;
            printf("    AVX512-8way: iterations: %10llu, time: %.6f s, hashes/s: %.2f\n",
                   hashes8, elapsed8, hashes8 / elapsed8);
            printf("               cycles: %12llu, cycles/hash: %8.2f, cycles/byte: %.4f\n",
                   (unsigned long long)cycles8,
                   (double)cycles8 / hashes8,
                   (double)cycles8 / (hashes8 * blk));
        }
#endif
    }

    free(buffer);
    return 0;
}