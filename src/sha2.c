#include <stddef.h>
/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Rhett Creighton */
#ifndef SHA2_LICENSE
/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Rhett Creighton */
#define SHA2_LICENSE
#endif
#include "sha2.h"
#include <string.h>
#include <stdlib.h>

/* 
 * Forward declarations of internal functions implemented in
 * specific hash implementation files
 */
int sha256_init(void *ctx);
int sha256_update(void *ctx, const void *data, size_t len);
int sha256_final(void *ctx, void *digest, size_t digest_size);

int sha224_init(void *ctx);
int sha224_final(void *ctx, void *digest, size_t digest_size);

int sha512_init(void *ctx);
int sha512_update(void *ctx, const void *data, size_t len);
int sha512_final(void *ctx, void *digest, size_t digest_size);

int sha384_init(void *ctx);
int sha384_final(void *ctx, void *digest, size_t digest_size);


/* Library version */
const char* sha2_version(void) {
    return "SHA2 Library v1.1.0";
}
    
    

/* Initialize a hash context with the specified algorithm */
int sha2_init(sha2_ctx *ctx, sha2_hash_type type) {
    if (!ctx) {
        return -1;
    }
    
    /* Clear context first to ensure all fields are initialized */
    memset(ctx, 0, sizeof(sha2_ctx));
    
    /* Set hash type */
    ctx->type = type;
    
    /* Call appropriate initialization function based on hash type */
    switch (type) {
        case SHA2_224:
            return sha224_init(ctx);
        case SHA2_256:
            return sha256_init(ctx);
        case SHA2_384:
            return sha384_init(ctx);
        case SHA2_512:
            return sha512_init(ctx);
        default:
            return -1;
    }
}
// EOF

/* Update hash with more data */
int sha2_update(sha2_ctx *ctx, const void *data, size_t len) {
    if (!ctx || !data) {
        return -1;
    }
    
    /* Call appropriate update function based on hash type */
    switch (ctx->type) {
        case SHA2_224:
        case SHA2_256:
            return sha256_update(ctx, data, len);
        case SHA2_384:
        case SHA2_512:
            return sha512_update(ctx, data, len);
        default:
            return -1;
    }
}

/* Finalize hash and get digest */
int sha2_final(sha2_ctx *ctx, void *digest, size_t digest_size) {
    if (!ctx || !digest) {
        return -1;
    }
    
    /* Call appropriate finalization function based on hash type */
    switch (ctx->type) {
        case SHA2_224:
            return sha224_final(ctx, digest, digest_size);
        case SHA2_256:
            return sha256_final(ctx, digest, digest_size);
        case SHA2_384:
            return sha384_final(ctx, digest, digest_size);
        case SHA2_512:
            return sha512_final(ctx, digest, digest_size);
        default:
            return -1;
    }
}

/* Get digest size for a hash type */
size_t sha2_get_digest_size(sha2_hash_type type) {
    switch (type) {
        case SHA2_224:
            return SHA224_DIGEST_SIZE;
        case SHA2_256:
            return SHA256_DIGEST_SIZE;
        case SHA2_384:
            return SHA384_DIGEST_SIZE;
        case SHA2_512:
            return SHA512_DIGEST_SIZE;
        default:
            return 0;
    }
}

/* Get block size for a hash type */
size_t sha2_get_block_size(sha2_hash_type type) {
    switch (type) {
        case SHA2_224:
        case SHA2_256:
            return SHA256_BLOCK_SIZE;
        case SHA2_384:
        case SHA2_512:
            return SHA512_BLOCK_SIZE;
        default:
            return 0;
    }
}

/* Compute hash in one operation */
int sha2_hash(sha2_hash_type type, const void *data, size_t len, void *digest, size_t digest_size) {
    sha2_ctx ctx;
    int ret;
    
    if (!data || !digest) {
        return -1;
    }
    
    /* Check if digest buffer is big enough */
    if (digest_size < sha2_get_digest_size(type)) {
        return -1;
    }
    
    /* Initialize, update, and finalize in one go */
    if ((ret = sha2_init(&ctx, type)) != 0) {
        return ret;
    }
    
    if ((ret = sha2_update(&ctx, data, len)) != 0) {
        return ret;
    }
    
return sha2_final(&ctx, digest, digest_size);
}

