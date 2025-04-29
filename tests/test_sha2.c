/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Rhett Creighton */

#include "sha2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Test vectors for SHA-2 and SHA-3 */
typedef struct {
    const char *msg;
    const char *sha224;
    const char *sha256;
    const char *sha384;
    const char *sha512;
} test_vector;

/* Helper to convert hex string to binary */
static void hex_to_bin(const char *hex, uint8_t *bin, size_t bin_size) {
    size_t i;
    char hex_byte[3];
    
    hex_byte[2] = '\0';
    for (i = 0; i < bin_size; i++) {
        hex_byte[0] = hex[i * 2];
        hex_byte[1] = hex[i * 2 + 1];
        bin[i] = (uint8_t)strtol(hex_byte, NULL, 16);
    }
}

/* Helper to convert binary to hex string */
static void bin_to_hex(const uint8_t *bin, size_t bin_size, char *hex) {
    size_t i;
    
    for (i = 0; i < bin_size; i++) {
        sprintf(hex + i * 2, "%02x", bin[i]);
    }
    hex[bin_size * 2] = '\0';
}

/* Run a hash test with a specific algorithm */
static int test_hash(sha2_hash_type type, const char *msg, const char *expected_hex) {
    uint8_t digest[SHA2_MAX_DIGEST_SIZE];
    size_t digest_size = sha2_get_digest_size(type);
    uint8_t expected[SHA2_MAX_DIGEST_SIZE];
    char result_hex[SHA2_MAX_DIGEST_SIZE * 2 + 1];
    int ret;
    
    /* Skip test if expected result is NULL */
    if (!expected_hex) {
        return 1;
    }
    
    /* Convert expected hex to binary */
    hex_to_bin(expected_hex, expected, digest_size);
    
    /* Compute the hash */
    ret = sha2_hash(type, msg, strlen(msg), digest, digest_size);
    if (ret != (int)digest_size) {
        printf("FAIL: sha2_hash returned %d, expected %zu\n", ret, digest_size);
        return 0;
    }
    
    /* Convert result back to hex for display */
    bin_to_hex(digest, digest_size, result_hex);
    
    /* Compare with expected result */
    if (memcmp(digest, expected, digest_size) != 0) {
        printf("FAIL: %s\n", result_hex);
        printf("Expected: %s\n", expected_hex);
        return 0;
    }
    
    return 1;
}

/* Test the hash function interface */
static int test_hash_function_interface(sha2_hash_type type, const char *msg, const char *expected_hex) {
    const sha2_hash_function *hash_func;
    void *ctx;
    uint8_t digest[SHA2_MAX_DIGEST_SIZE];
    uint8_t expected[SHA2_MAX_DIGEST_SIZE];
    int ret;
    
    /* Skip test if expected result is NULL */
    if (!expected_hex) {
        return 1;
    }
    
    /* Get the hash function instance */
    hash_func = sha2_get_hash_function(type);
    if (!hash_func) {
        printf("FAIL: sha2_get_hash_function returned NULL\n");
        return 0;
    }
    
    /* Allocate context */
    ctx = malloc(hash_func->ctx_size);
    if (!ctx) {
        printf("FAIL: Failed to allocate context\n");
        return 0;
    }
    
    /* Convert expected hex to binary */
    hex_to_bin(expected_hex, expected, hash_func->digest_size);
    
    /* Initialize, update, and finalize */
    ret = hash_func->init(ctx);
    if (ret != 0) {
        printf("FAIL: init returned %d\n", ret);
        free(ctx);
        return 0;
    }
    
    ret = hash_func->update(ctx, msg, strlen(msg));
    if (ret != 0) {
        printf("FAIL: update returned %d\n", ret);
        free(ctx);
        return 0;
    }
    
    ret = hash_func->final(ctx, digest, hash_func->digest_size);
    if (ret != (int)hash_func->digest_size) {
        printf("FAIL: final returned %d, expected %zu\n", ret, hash_func->digest_size);
        free(ctx);
        return 0;
    }
    
    /* Compare with expected result */
    if (memcmp(digest, expected, hash_func->digest_size) != 0) {
        char result_hex[SHA2_MAX_DIGEST_SIZE * 2 + 1];
        bin_to_hex(digest, hash_func->digest_size, result_hex);
        printf("FAIL: %s\n", result_hex);
        printf("Expected: %s\n", expected_hex);
        free(ctx);
        return 0;
    }
    
    free(ctx);
    return 1;
}

int main() {
    int tests_passed = 0;
    int tests_failed = 0;
    int i;
    
    /* Test vectors from various standards */
    test_vector vectors[] = {
        { 
            /* Empty string */
            "",
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        },
        { 
            /* "abc" */
            "abc",
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        }
    };
    
    printf("SHA-2 Library Tests\n");
    printf("=================\n");
    
    for (i = 0; i < (int)(sizeof(vectors) / sizeof(vectors[0])); i++) {
        printf("Test vector %d: \"%s\"\n", i + 1, vectors[i].msg);
        
        /* Test direct hash API */
        printf("  Testing direct API:\n");
        
        printf("    SHA-224: ");
        if (test_hash(SHA2_224, vectors[i].msg, vectors[i].sha224)) {
            printf("PASS\n");
            tests_passed++;
        } else {
            tests_failed++;
        }
        
        printf("    SHA-256: ");
        if (test_hash(SHA2_256, vectors[i].msg, vectors[i].sha256)) {
            printf("PASS\n");
            tests_passed++;
        } else {
            tests_failed++;
        }
        
        printf("    SHA-384: ");
        if (test_hash(SHA2_384, vectors[i].msg, vectors[i].sha384)) {
            printf("PASS\n");
            tests_passed++;
        } else {
            tests_failed++;
        }
        
        printf("    SHA-512: ");
        if (test_hash(SHA2_512, vectors[i].msg, vectors[i].sha512)) {
            printf("PASS\n");
            tests_passed++;
        } else {
            tests_failed++;
        }
        
        
        /* Test hash function interface */
        printf("  Testing hash function interface:\n");
        
        printf("    SHA-224: ");
        if (test_hash_function_interface(SHA2_224, vectors[i].msg, vectors[i].sha224)) {
            printf("PASS\n");
            tests_passed++;
        } else {
            tests_failed++;
        }
        
        printf("    SHA-256: ");
        if (test_hash_function_interface(SHA2_256, vectors[i].msg, vectors[i].sha256)) {
            printf("PASS\n");
            tests_passed++;
        } else {
            tests_failed++;
        }
        
        printf("    SHA-384: ");
        if (test_hash_function_interface(SHA2_384, vectors[i].msg, vectors[i].sha384)) {
            printf("PASS\n");
            tests_passed++;
        } else {
            tests_failed++;
        }
        
        printf("    SHA-512: ");
        if (test_hash_function_interface(SHA2_512, vectors[i].msg, vectors[i].sha512)) {
            printf("PASS\n");
            tests_passed++;
        } else {
            tests_failed++;
        }
        
    }
    
    printf("\nTest summary: %d passed, %d failed\n", tests_passed, tests_failed);
    
    return tests_failed ? 1 : 0;
}