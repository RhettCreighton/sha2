/**
 * @file sha2_benchmark_mt.c
 * @brief Multi-threaded SHA-256 benchmark using SHA-NI multi-block transform
 */
#ifndef BENCH_SHA256_MT_LICENSE
/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Rhett Creighton */
#define BENCH_SHA256_MT_LICENSE
#endif

#define _POSIX_C_SOURCE 199309L
#include "sha2.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <sched.h>
// Declaration for the SHA-NI multi-block transform
extern void sha256_ni_transform(uint32_t *digest, const void *data, uint64_t numBlocks);

// High-resolution timestamp (seconds)
static inline double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

// Thread argument structure
typedef struct {
    size_t blk;
    unsigned long M;
    uint8_t *buffer;
    volatile int *start_flag;
    double time_sec;
    unsigned long long count;
} thread_arg;

// Thread function: runs SHA-NI multi-block transform in a tight loop
static void* thread_func(void *arg_) {
    thread_arg *arg = (thread_arg*)arg_;
    sha2_ctx ctx;
    sha2_init(&ctx, SHA2_256);
    // Warm-up
    for (int i = 0; i < 10; i++) {
        sha256_ni_transform(ctx.u.sha256.state, arg->buffer, arg->M);
    }
    // Wait for start signal
    while (!*(arg->start_flag)) {
        sched_yield();
    }
    // Benchmark loop
    double t_start = now();
    unsigned long long cnt = 0;
    while (now() - t_start < arg->time_sec) {
        sha256_ni_transform(ctx.u.sha256.state, arg->buffer, arg->M);
        cnt++;
    }
    arg->count = cnt;
    return NULL;
}

int main(void) {
    const size_t blk = SHA256_BLOCK_SIZE; // 64 bytes
    const double TIME_SEC = 1.0;
    const unsigned long M = 256; // blocks per transform call
    int nthreads = sysconf(_SC_NPROCESSORS_ONLN);
    pthread_t *threads = malloc(sizeof(pthread_t) * nthreads);
    thread_arg *args = malloc(sizeof(thread_arg) * nthreads);
    if (!threads || !args) {
        fprintf(stderr, "Allocation failure\n");
        return 1;
    }
    // Allocate and initialize buffer (M * 64 bytes)
    uint8_t *buffer = malloc(blk * M);
    if (!buffer) {
        fprintf(stderr, "Allocation failure\n");
        return 1;
    }
    for (size_t i = 0; i < blk * M; i++) {
        buffer[i] = (uint8_t)(i & 0xFF);
    }
    volatile int start_flag = 0;
    // Launch threads
    for (int t = 0; t < nthreads; t++) {
        args[t].blk = blk;
        args[t].M = M;
        args[t].buffer = buffer;
        args[t].start_flag = &start_flag;
        args[t].time_sec = TIME_SEC;
        args[t].count = 0;
        if (pthread_create(&threads[t], NULL, thread_func, &args[t]) != 0) {
            perror("pthread_create");
            return 1;
        }
    }
    // Start benchmark
    start_flag = 1;
    // Join threads and accumulate counts
    unsigned long long total_calls = 0;
    for (int t = 0; t < nthreads; t++) {
        pthread_join(threads[t], NULL);
        total_calls += args[t].count;
    }
    unsigned long long total_hashes = total_calls * M;
    printf("SHA-256 Multi-threaded SHA-NI multi-block(%lu) benchmark\n", M);
    printf("Threads: %d, Block size: %zu bytes, blocks per call: %lu\n",
           nthreads, blk, M);
    printf("Total calls: %llu, Total hashes: %llu\n",
           total_calls, total_hashes);
    printf("Time: %.6f s, hashes/s: %.2f\n",
           TIME_SEC, (double)total_hashes / TIME_SEC);
    free(buffer);
    free(threads);
    free(args);
    return 0;
}