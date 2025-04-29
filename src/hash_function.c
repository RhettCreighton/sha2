/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Rhett Creighton */
#include "sha2.h"
#include <stdlib.h>
#include <string.h>

/* Forward declarations for the internal hash functions */
int sha224_init(void *ctx);
int sha256_init(void *ctx);
int sha256_update(void *ctx, const void *data, size_t len);
int sha224_final(void *ctx, void *digest, size_t digest_size);
int sha256_final(void *ctx, void *digest, size_t digest_size);

int sha384_init(void *ctx);
int sha512_init(void *ctx);
int sha512_update(void *ctx, const void *data, size_t len);
int sha384_final(void *ctx, void *digest, size_t digest_size);
int sha512_final(void *ctx, void *digest, size_t digest_size);


/* Static hash function instances for each type */
static const sha2_hash_function sha224_hash_function = {
    sha224_init,
    sha256_update,
    sha224_final,
    sizeof(sha2_ctx),
    SHA224_DIGEST_SIZE,
    "SHA-224"
};

static const sha2_hash_function sha256_hash_function = {
    sha256_init,
    sha256_update,
    sha256_final,
    sizeof(sha2_ctx),
    SHA256_DIGEST_SIZE,
    "SHA-256"
};

static const sha2_hash_function sha384_hash_function = {
    sha384_init,
    sha512_update,
    sha384_final,
    sizeof(sha2_ctx),
    SHA384_DIGEST_SIZE,
    "SHA-384"
};

static const sha2_hash_function sha512_hash_function = {
    sha512_init,
    sha512_update,
    sha512_final,
    sizeof(sha2_ctx),
    SHA512_DIGEST_SIZE,
    "SHA-512"
};


/* Get a hash function instance by type */
const sha2_hash_function* sha2_get_hash_function(sha2_hash_type type) {
    switch (type) {
        case SHA2_224:
            return &sha224_hash_function;
        case SHA2_256:
            return &sha256_hash_function;
        case SHA2_384:
            return &sha384_hash_function;
        case SHA2_512:
            return &sha512_hash_function;
        default:
            return NULL;
    }
}


/* Create a new hash function instance with default values */
sha2_hash_function* sha2_create_hash_function(
    const char *name,
    size_t ctx_size,
    size_t digest_size,
    int (*init)(void *ctx),
    int (*update)(void *ctx, const void *data, size_t len),
    int (*final)(void *ctx, void *digest, size_t digest_size)
) {
    sha2_hash_function *hash_func;
    
    if (!name || !init || !update || !final || ctx_size == 0 || digest_size == 0) {
        return NULL;
    }
    
    hash_func = (sha2_hash_function *)malloc(sizeof(sha2_hash_function));
    if (!hash_func) {
        return NULL;
    }
    
    hash_func->init = init;
    hash_func->update = update;
    hash_func->final = final;
    hash_func->ctx_size = ctx_size;
    hash_func->digest_size = digest_size;
    
    /* Copy the name */
    size_t name_len = strlen(name);
    char* name_copy = (char*)malloc(name_len + 1);
    if (!name_copy) {
        free(hash_func);
        return NULL;
    }
    
    strcpy(name_copy, name);
    hash_func->name = name_copy;
    
    return hash_func;
}

/* Free a hash function instance created with sha2_create_hash_function */
void sha2_free_hash_function(sha2_hash_function *hash_func) {
    if (hash_func) {
        free((void *)hash_func->name);  /* Cast needed to remove const */
        free(hash_func);
    }
}
