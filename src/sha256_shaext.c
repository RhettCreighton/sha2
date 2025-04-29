/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Rhett Creighton */
/*
 * sha256_shaext.c
 *
 * SHA-256 compression using Intel SHA Extensions (SHA-NI)
 */
/* Wrapper for SHA-NI accelerated single-block SHA-256 compression */
#include <stddef.h>
#include "sha2.h"
extern void sha256_process_block(sha2_ctx *ctx, const uint8_t *block);
extern void sha256_ni_transform(uint32_t *digest, const void *data, uint64_t numBlocks);

void sha256_process_block_shaext(sha2_ctx *ctx, const uint8_t *block) {
    // Always invoke the SHA-NI accelerated transform for single-block processing
    sha256_ni_transform(ctx->u.sha256.state, block, 1);
}
