#ifndef EX_FS_LICENSE
/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Rhett Creighton */
#define EX_FS_LICENSE
#endif
#include "sha2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * This example demonstrates how to use the SHA2 library to implement
 * Fiat-Shamir transformations for the sumcheck protocol.
 * 
 * The actual integration with the sumcheck protocol would be implemented
 * by modifying the protocol.c and proof.c files in the sumcheck_protocol
 * project to use the hash function interface provided by this library.
 */

/* Mock field element structure (simulating what would be in sumcheck_protocol) */
typedef struct {
    uint8_t data[32];
} field_element;

/* Mock univariate polynomial structure (simulating what would be in sumcheck_protocol) */
typedef struct {
    field_element coefficients[2];  /* Degree 1 polynomial */
    int num_coefficients;
} univariate_poly;

/* Serialize a field element for hashing (in a real implementation, this would be in protocol.c) */
static void serialize_field_element(const field_element *element, uint8_t *buffer) {
    memcpy(buffer, element->data, sizeof(element->data));
}

/* Serialize a univariate polynomial for hashing (in a real implementation, this would be in protocol.c) */
static void serialize_univariate_poly(const univariate_poly *poly, uint8_t *buffer) {
    size_t i;
    for (i = 0; i < (size_t)poly->num_coefficients; i++) {
        serialize_field_element(&poly->coefficients[i], buffer + i * sizeof(field_element));
    }
}

/* Generate a Fiat-Shamir challenge from a univariate polynomial */
static void generate_fiat_shamir_challenge(
    const univariate_poly *poly,
    uint32_t round,
    const void *previous_challenges,
    size_t previous_challenges_len,
    field_element *challenge,
    sha2_hash_type hash_type
) {
    /* Get the hash function */
    const sha2_hash_function *hash_func = sha2_get_hash_function(hash_type);
    if (!hash_func) {
        fprintf(stderr, "Error: Failed to get hash function\n");
        return;
    }
    
    /* Allocate hash context */
    void *ctx = malloc(hash_func->ctx_size);
    if (!ctx) {
        fprintf(stderr, "Error: Failed to allocate hash context\n");
        return;
    }
    
    /* Initialize hash */
    if (hash_func->init(ctx) != 0) {
        fprintf(stderr, "Error: Failed to initialize hash context\n");
        free(ctx);
        return;
    }
    
    /* Serialize and hash the polynomial */
    uint8_t *poly_data = malloc(poly->num_coefficients * sizeof(field_element));
    if (!poly_data) {
        fprintf(stderr, "Error: Failed to allocate buffer for polynomial\n");
        free(ctx);
        return;
    }
    
    serialize_univariate_poly(poly, poly_data);
    
    /* Update hash with polynomial data */
    if (hash_func->update(ctx, poly_data, poly->num_coefficients * sizeof(field_element)) != 0) {
        fprintf(stderr, "Error: Failed to update hash with polynomial\n");
        free(poly_data);
        free(ctx);
        return;
    }
    
    free(poly_data);
    
    /* Update hash with round number */
    if (hash_func->update(ctx, &round, sizeof(round)) != 0) {
        fprintf(stderr, "Error: Failed to update hash with round number\n");
        free(ctx);
        return;
    }
    
    /* Update hash with previous challenges if any */
    if (previous_challenges && previous_challenges_len > 0) {
        if (hash_func->update(ctx, previous_challenges, previous_challenges_len) != 0) {
            fprintf(stderr, "Error: Failed to update hash with previous challenges\n");
            free(ctx);
            return;
        }
    }
    
    /* Finalize hash and get digest */
    uint8_t digest[SHA2_MAX_DIGEST_SIZE];
    if (hash_func->final(ctx, digest, hash_func->digest_size) <= 0) {
        fprintf(stderr, "Error: Failed to finalize hash\n");
        free(ctx);
        return;
    }
    
    /* Free context */
    free(ctx);
    
    /* Format digest as a field element (in a real implementation, this would use BTF conversions) */
    memset(challenge->data, 0, sizeof(challenge->data));
    memcpy(challenge->data, digest, hash_func->digest_size > sizeof(challenge->data) ? 
           sizeof(challenge->data) : hash_func->digest_size);
}

/* Helper to print a field element as hex */
static void print_field_element(const field_element *element) {
    int i;
    for (i = 0; i < 8; i++) {  /* Print first 8 bytes for brevity */
        printf("%02x", element->data[i]);
    }
    printf("...");
}

int main() {
    /* Create a mock univariate polynomial */
    univariate_poly poly;
    poly.num_coefficients = 2;
    
    /* Initialize with some sample data */
    memset(&poly.coefficients[0], 0xaa, sizeof(field_element));
    memset(&poly.coefficients[1], 0xbb, sizeof(field_element));
    
    /* Array to hold challenges */
    field_element challenges[3];
    
    printf("Fiat-Shamir Transformation Example\n");
    printf("==================================\n");
    
    /* Generate challenges for three rounds using SHA-256 */
    printf("\nUsing SHA-256:\n");
    for (uint32_t round = 0; round < 3; round++) {
        printf("Round %u: ", round);
        
        /* Generate challenge */
        generate_fiat_shamir_challenge(
            &poly, 
            round,
            round > 0 ? challenges : NULL,  /* Previous challenges */
            round * sizeof(field_element),  /* Length of previous challenges */
            &challenges[round],
            SHA2_256
        );
        
        /* Print challenge */
        printf("Challenge = ");
        print_field_element(&challenges[round]);
        printf("\n");
        
        /* Update polynomial for next round (in a real protocol, this would be based on the challenge) */
        poly.coefficients[0].data[0] ^= challenges[round].data[0];
        poly.coefficients[1].data[0] ^= challenges[round].data[1];
    }
    
    /* Reset the polynomial */
    memset(&poly.coefficients[0], 0xaa, sizeof(field_element));
    memset(&poly.coefficients[1], 0xbb, sizeof(field_element));
    
    /* Generate challenges for three rounds using SHA-512 */
    printf("\nUsing SHA-512:\n");
    for (uint32_t round = 0; round < 3; round++) {
        printf("Round %u: ", round);
        
        /* Generate challenge */
        generate_fiat_shamir_challenge(
            &poly, 
            round,
            round > 0 ? challenges : NULL,  /* Previous challenges */
            round * sizeof(field_element),  /* Length of previous challenges */
            &challenges[round],
            SHA2_512
        );
        
        /* Print challenge */
        printf("Challenge = ");
        print_field_element(&challenges[round]);
        printf("\n");
        
        /* Update polynomial for next round (in a real protocol, this would be based on the challenge) */
        poly.coefficients[0].data[0] ^= challenges[round].data[0];
        poly.coefficients[1].data[0] ^= challenges[round].data[1];
    }
    
    printf("\nIn a real sumcheck protocol implementation:\n");
    printf("1. The sumcheck_protocol library would use this SHA2 library for Fiat-Shamir\n");
    printf("2. The hash function would be configurable via the protocol's API\n");
    printf("3. Real field elements and polynomials would be used instead of mocks\n");
    
    return 0;
}