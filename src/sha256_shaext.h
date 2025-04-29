/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Rhett Creighton */

#ifndef SHA256_SHAEXT_H
#define SHA256_SHAEXT_H

#include "sha2.h"

// SHA-256 block process wrapper: uses SHA-NI if available, else scalar fallback
// This function is defined in sha256_shaext.c
void sha256_process_block_shaext(sha2_ctx *ctx, const uint8_t *block);

#endif // SHA256_SHAEXT_H
