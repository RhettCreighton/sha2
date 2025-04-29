/**
 * @file sha2_benchmark512.c
 * @brief Benchmark example: measure SHA-512 hashes per second
 */
#define _POSIX_C_SOURCE 199309L
#include "sha2.h"
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#ifndef BENCH_SHA512_LICENSE
/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Rhett Creighton */
#define BENCH_SHA512_LICENSE
#endif
static inline uint64_t rdtsc(void) {
    unsigned int lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

int main(void) {
    const size_t sizes[] = { 128, 1024, 4096, 1048576 };
    const int num_sizes = sizeof(sizes) / sizeof(sizes[0]);
    uint8_t *buffer = malloc(sizes[num_sizes - 1]);
    uint8_t digest[SHA2_MAX_DIGEST_SIZE];
    if (!buffer) return 1;
    for (size_t i = 0; i < sizes[num_sizes - 1]; i++) buffer[i] = (uint8_t)(i & 0xFF);

    printf("SHA-512 Benchmark (time + cycles)\n");
    const double TIME_SEC = 1.0;

    for (int idx = 0; idx < num_sizes; idx++) {
        size_t blk = sizes[idx];
        for (int i = 0; i < 10; i++) sha2_hash(SHA2_512, buffer, blk, digest, SHA512_DIGEST_SIZE);
        double t_start = now(); unsigned long long count = 0;
        while (now() - t_start < TIME_SEC) {
            sha2_hash(SHA2_512, buffer, blk, digest, SHA512_DIGEST_SIZE);
            count++;
        }
        double elapsed = now() - t_start;
        uint64_t c_start = rdtsc();
        for (unsigned long long i = 0; i < count; i++)
            sha2_hash(SHA2_512, buffer, blk, digest, SHA512_DIGEST_SIZE);
        uint64_t cycles = rdtsc() - c_start;
        printf("[%6zu bytes] hashes/s: %.2f, cycles/hash: %.2f, cycles/byte: %.4f\n",
               blk, count/elapsed, (double)cycles/count, (double)cycles/(count*blk));
        // Vector benchmarks for 128-byte blocks
        if (blk == 128) {
#ifdef __AVX2__
            // AVX2 4-way parallel
            sha2_ctx ctx0, ctx1, ctx2, ctx3;
            sha2_init(&ctx0, SHA2_512);
            sha2_init(&ctx1, SHA2_512);
            sha2_init(&ctx2, SHA2_512);
            sha2_init(&ctx3, SHA2_512);
            uint64_t st0[8], st1[8], st2[8], st3[8];
            memcpy(st0, ctx0.u.sha512.state, sizeof(st0));
            memcpy(st1, ctx1.u.sha512.state, sizeof(st1));
            memcpy(st2, ctx2.u.sha512.state, sizeof(st2));
            memcpy(st3, ctx3.u.sha512.state, sizeof(st3));
            // Warm-up
            for (int i = 0; i < 10; i++) {
                sha512_process4_avx2(st0, st1, st2, st3,
                                     buffer, buffer + 128,
                                     buffer + 256, buffer + 384);
            }
            // Time-based measurement
            double t4_start = now(); unsigned long long count4 = 0;
            while (now() - t4_start < TIME_SEC) {
                sha512_process4_avx2(st0, st1, st2, st3,
                                     buffer, buffer + 128,
                                     buffer + 256, buffer + 384);
                count4++;
            }
            double elapsed4 = now() - t4_start;
            // Cycle-based measurement
            uint64_t c4_start = rdtsc();
            for (unsigned long long i = 0; i < count4; i++) {
                sha512_process4_avx2(st0, st1, st2, st3,
                                     buffer, buffer + 128,
                                     buffer + 256, buffer + 384);
            }
            uint64_t c4_end = rdtsc(); uint64_t cycles4 = c4_end - c4_start;
            unsigned long long hashes4 = count4 * 4ULL;
            printf("    AVX2-4way: hashes/s: %.2f, cycles/hash: %.2f, cycles/byte: %.4f\n",
                   hashes4 / elapsed4,
                   (double)cycles4 / hashes4,
                   (double)cycles4 / (hashes4 * blk));
#endif
#ifdef __AVX512F__
            // AVX-512 8-way parallel
            sha2_ctx ctx4[8]; uint64_t st4[8][8];
            const uint8_t *blocks8[8] = { buffer, buffer + 128,
                                          buffer + 256, buffer + 384,
                                          buffer + 512, buffer + 640,
                                          buffer + 768, buffer + 896 };
            for (int i = 0; i < 8; i++) {
                sha2_init(&ctx4[i], SHA2_512);
                memcpy(st4[i], ctx4[i].u.sha512.state, 8 * sizeof(uint64_t));
            }
            // Warm-up
            for (int i = 0; i < 10; i++) {
                sha512_process8_avx512(st4[0],st4[1],st4[2],st4[3],
                                      st4[4],st4[5],st4[6],st4[7],
                                      blocks8[0],blocks8[1],blocks8[2],blocks8[3],
                                      blocks8[4],blocks8[5],blocks8[6],blocks8[7]);
            }
            // Time-based measurement
            double t8_start = now(); unsigned long long count8 = 0;
            while (now() - t8_start < TIME_SEC) {
                sha512_process8_avx512(st4[0],st4[1],st4[2],st4[3],
                                      st4[4],st4[5],st4[6],st4[7],
                                      blocks8[0],blocks8[1],blocks8[2],blocks8[3],
                                      blocks8[4],blocks8[5],blocks8[6],blocks8[7]);
                count8++;
            }
            double elapsed8 = now() - t8_start;
            // Cycle-based measurement
            uint64_t c8_start = rdtsc();
            for (unsigned long long i = 0; i < count8; i++) {
                sha512_process8_avx512(st4[0],st4[1],st4[2],st4[3],
                                      st4[4],st4[5],st4[6],st4[7],
                                      blocks8[0],blocks8[1],blocks8[2],blocks8[3],
                                      blocks8[4],blocks8[5],blocks8[6],blocks8[7]);
            }
            uint64_t c8_end = rdtsc(); uint64_t cycles8 = c8_end - c8_start;
            unsigned long long hashes8 = count8 * 8ULL;
            printf("    AVX512-8way: hashes/s: %.2f, cycles/hash: %.2f, cycles/byte: %.4f\n",
                   hashes8 / elapsed8,
                   (double)cycles8 / hashes8,
                   (double)cycles8 / (hashes8 * blk));
#endif
        }
    }
    free(buffer);
    return 0;
}