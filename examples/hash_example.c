#ifndef EX_HASH_LICENSE
/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Rhett Creighton */
#define EX_HASH_LICENSE
#endif
#include "sha2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Helper to convert binary to hex string */
static void bin_to_hex(const uint8_t *bin, size_t bin_size, char *hex) {
    size_t i;
    
    for (i = 0; i < bin_size; i++) {
        sprintf(hex + i * 2, "%02x", bin[i]);
    }
    hex[bin_size * 2] = '\0';
}

int main(int argc, char *argv[]) {
    const char *input;
    uint8_t digest[SHA2_MAX_DIGEST_SIZE];
    char hex_digest[SHA2_MAX_DIGEST_SIZE * 2 + 1];
    sha2_ctx ctx;
    int ret;
    
    /* Check for input string argument */
    if (argc != 2) {
        printf("Usage: %s <string>\n", argv[0]);
        printf("Example: %s \"Hello, World!\"\n", argv[0]);
        return 1;
    }
    
    input = argv[1];
    printf("Input: \"%s\"\n\n", input);
    
    /* One-shot hashing examples */
    printf("One-shot hashing examples:\n");
    printf("-------------------------\n");
    
    /* SHA-256 example */
    printf("SHA-256: ");
    ret = sha2_hash(SHA2_256, input, strlen(input), digest, sizeof(digest));
    if (ret <= 0) {
        printf("Error hashing input\n");
        return 1;
    }
    bin_to_hex(digest, SHA256_DIGEST_SIZE, hex_digest);
    printf("%s\n", hex_digest);
    
    /* SHA-512 example */
    printf("SHA-512: ");
    ret = sha2_hash(SHA2_512, input, strlen(input), digest, sizeof(digest));
    if (ret <= 0) {
        printf("Error hashing input\n");
        return 1;
    }
    bin_to_hex(digest, SHA512_DIGEST_SIZE, hex_digest);
    printf("%s\n", hex_digest);
    
    printf("\n");
    
    /* Incremental hashing example */
    printf("Incremental hashing example (SHA-256):\n");
    printf("------------------------------------\n");
    
    /* Initialize context */
    if (sha2_init(&ctx, SHA2_256) != 0) {
        printf("Error initializing context\n");
        return 1;
    }
    
    /* Update with first half of input */
    size_t half_len = strlen(input) / 2;
    printf("Update with first %zu bytes: \"%.*s\"\n", half_len, (int)half_len, input);
    if (sha2_update(&ctx, input, half_len) != 0) {
        printf("Error updating hash\n");
        return 1;
    }
    
    /* Update with second half of input */
    printf("Update with next %zu bytes: \"%s\"\n", strlen(input) - half_len, input + half_len);
    if (sha2_update(&ctx, input + half_len, strlen(input) - half_len) != 0) {
        printf("Error updating hash\n");
        return 1;
    }
    
    /* Finalize and get digest */
    if (sha2_final(&ctx, digest, sizeof(digest)) <= 0) {
        printf("Error finalizing hash\n");
        return 1;
    }
    bin_to_hex(digest, SHA256_DIGEST_SIZE, hex_digest);
    printf("Final digest: %s\n\n", hex_digest);
    
    /* Hash function interface example */
    printf("Hash function interface example (SHA-512):\n");
    printf("---------------------------------------\n");
    
    /* Get the hash function */
    const sha2_hash_function *hash_func = sha2_get_hash_function(SHA2_512);
    if (!hash_func) {
        printf("Error getting hash function\n");
        return 1;
    }
    
    printf("Using hash function: %s (digest size: %zu bytes)\n", 
           hash_func->name, hash_func->digest_size);
    
    /* Allocate context */
    void *hash_ctx = malloc(hash_func->ctx_size);
    if (!hash_ctx) {
        printf("Error allocating context\n");
        return 1;
    }
    
    /* Initialize, update, and finalize */
    if (hash_func->init(hash_ctx) != 0) {
        printf("Error initializing context\n");
        free(hash_ctx);
        return 1;
    }
    
    if (hash_func->update(hash_ctx, input, strlen(input)) != 0) {
        printf("Error updating hash\n");
        free(hash_ctx);
        return 1;
    }
    
    if (hash_func->final(hash_ctx, digest, hash_func->digest_size) <= 0) {
        printf("Error finalizing hash\n");
        free(hash_ctx);
        return 1;
    }
    
    bin_to_hex(digest, hash_func->digest_size, hex_digest);
    printf("Final digest: %s\n", hex_digest);
    
    /* Clean up */
    free(hash_ctx);
    
    return 0;
}