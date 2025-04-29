/**
 * @file sha2.h
 * @brief Implementation of SHA-2 hash functions with support for integration with sumcheck protocol
 *
 * This library implements the SHA-2 family (SHA-224, SHA-256, SHA-384, SHA-512) of hash functions,
 * designed to be compatible with the sumcheck protocol for Fiat-Shamir transformations.
 * It includes a common interface for hash functions that can be used by other protocols.
 */

/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Rhett Creighton */

#ifndef SHA2_H
#define SHA2_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Hash function types supported by this library */
typedef enum {
    SHA2_224 = 0,   /**< SHA-224 hash function */
    SHA2_256 = 1,   /**< SHA-256 hash function */
    SHA2_384 = 2,   /**< SHA-384 hash function */
    SHA2_512 = 3,   /**< SHA-512 hash function */
} sha2_hash_type;

/** Output size of each hash function in bytes */
#define SHA224_DIGEST_SIZE 28
#define SHA256_DIGEST_SIZE 32
#define SHA384_DIGEST_SIZE 48
#define SHA512_DIGEST_SIZE 64

/** Maximum digest size among all supported hash functions */
#define SHA2_MAX_DIGEST_SIZE 64

/** Block size of each hash function in bytes */
#define SHA224_BLOCK_SIZE 64
#define SHA256_BLOCK_SIZE 64
#define SHA384_BLOCK_SIZE 128
#define SHA512_BLOCK_SIZE 128

/** Maximum block size among all supported hash functions */
#define SHA2_MAX_BLOCK_SIZE 128

/**
 * @struct sha2_ctx
 * @brief Context structure for SHA-2 hash functions
 * 
 * This structure contains the state for a hashing operation.
 * It is designed to be opaque to users, with internal fields
 * depending on the specific hash variant.
 */
typedef struct {
    sha2_hash_type type;            /**< Type of hash function */
    union {
        struct {
            uint32_t state[8];      /**< State for SHA-224/256 */
            uint8_t buffer[64];     /**< Buffer for SHA-224/256 */
            uint64_t total_bytes;   /**< Total bytes processed */
        } sha256;
        struct {
            uint64_t state[8];      /**< State for SHA-384/512 */
            uint8_t buffer[128];    /**< Buffer for SHA-384/512 */
            uint64_t total_bytes[2];/**< Total bytes processed (128-bit counter) */
        } sha512;
    } u;
} sha2_ctx;

/**
 * @brief Initialize the hash context for a specific hash algorithm
 *
 * @param ctx Pointer to the hash context to initialize
 * @param type Type of hash function to use
 * @return 0 on success, -1 on error
 */
int sha2_init(sha2_ctx *ctx, sha2_hash_type type);

/**
 * @brief Update the hash context with new data
 *
 * @param ctx Pointer to the hash context
 * @param data Pointer to the data to hash
 * @param len Length of the data in bytes
 * @return 0 on success, -1 on error
 */
int sha2_update(sha2_ctx *ctx, const void *data, size_t len);

/**
 * @brief Finalize the hash and get the digest
 *
 * @param ctx Pointer to the hash context
 * @param digest Pointer to buffer to receive the digest
 * @param digest_size Size of the digest buffer in bytes
 * @return Number of bytes written to digest on success, -1 on error
 */
int sha2_final(sha2_ctx *ctx, void *digest, size_t digest_size);

/**
 * @brief Compute hash in one operation
 *
 * @param type Type of hash function to use
 * @param data Pointer to the data to hash
 * @param len Length of the data in bytes
 * @param digest Pointer to buffer to receive the digest
 * @param digest_size Size of the digest buffer in bytes
 * @return Number of bytes written to digest on success, -1 on error
 */
int sha2_hash(sha2_hash_type type, const void *data, size_t len, void *digest, size_t digest_size);

/**
 * @brief Get the digest size for a hash type
 *
 * @param type Type of hash function
 * @return Size of the digest in bytes, or 0 if unknown
 */
size_t sha2_get_digest_size(sha2_hash_type type);

/**
 * @brief Get the block size for a hash type
 *
 * @param type Type of hash function
 * @return Size of the block in bytes, or 0 if unknown
 */
size_t sha2_get_block_size(sha2_hash_type type);

/**
 * @brief Library information
 *
 * @return Version string for the library
 */
const char* sha2_version(void);

/*
 * HashFunction interface for pluggable hash functions
 */

/**
 * @struct sha2_hash_function
 * @brief Interface for pluggable hash functions
 * 
 * This structure provides a generic interface for hash functions
 * that can be used with other libraries like sumcheck_protocol.
 */
typedef struct sha2_hash_function {
    /** Initialize the hash context */
    int (*init)(void *ctx);
    
    /** Update the hash context with new data */
    int (*update)(void *ctx, const void *data, size_t len);
    
    /** Finalize the hash and get the digest */
    int (*final)(void *ctx, void *digest, size_t digest_size);
    
    /** Size of the hash context structure */
    size_t ctx_size;
    
    /** Size of the digest output */
    size_t digest_size;
    
    /** Human-readable name of the hash function */
    const char *name;
} sha2_hash_function;

/**
 * @brief Get a hash function instance by type
 *
 * @param type Type of hash function
 * @return Pointer to hash function instance, or NULL if unsupported
 */
const sha2_hash_function* sha2_get_hash_function(sha2_hash_type type);

/**
 * @brief Create a new hash function instance with default values
 * 
 * @param name Human-readable name of the hash function
 * @param ctx_size Size of the hash context structure
 * @param digest_size Size of the digest output
 * @param init Initialize function
 * @param update Update function
 * @param final Finalize function
 * @return Pointer to newly allocated hash function instance, or NULL on error
 */
sha2_hash_function* sha2_create_hash_function(
    const char *name,
    size_t ctx_size,
    size_t digest_size,
    int (*init)(void *ctx),
    int (*update)(void *ctx, const void *data, size_t len),
    int (*final)(void *ctx, void *digest, size_t digest_size)
);

/**
 * @brief Free a hash function instance created with sha2_create_hash_function
 * 
 * @param hash_func Pointer to hash function instance to free
 */
void sha2_free_hash_function(sha2_hash_function *hash_func);

#ifdef __AVX2__
/**
 * @brief Process four independent 512-bit blocks in parallel using AVX2
 * @param state0..3 Four 8-word state arrays (a-h) to update
 * @param block0..3 Four pointers to 64-byte input blocks
 */
void sha256_process4_avx2(
    uint32_t state0[8], uint32_t state1[8],
    uint32_t state2[8], uint32_t state3[8],
    const uint8_t *block0, const uint8_t *block1,
    const uint8_t *block2, const uint8_t *block3
);
#endif
#ifdef __AVX2__
/**
 * @brief Process four independent 1024-bit blocks in parallel using AVX2
 *        (stub implementation: serial fallback)
 * @param state0..3 Four 8-word state arrays to update
 * @param block0..3 Four pointers to 128-byte input blocks
 */
void sha512_process4_avx2(
    uint64_t state0[8], uint64_t state1[8], uint64_t state2[8], uint64_t state3[8],
    const uint8_t *block0, const uint8_t *block1,
    const uint8_t *block2, const uint8_t *block3
);
#endif
#ifdef __AVX512F__
/**
 * @brief Process eight independent 1024-bit blocks in parallel using AVX-512
 *        (optional stub)
 */
void sha512_process8_avx512(
    uint64_t state0[8], uint64_t state1[8], uint64_t state2[8], uint64_t state3[8],
    uint64_t state4[8], uint64_t state5[8], uint64_t state6[8], uint64_t state7[8],
    const uint8_t *block0, const uint8_t *block1, const uint8_t *block2, const uint8_t *block3,
    const uint8_t *block4, const uint8_t *block5, const uint8_t *block6, const uint8_t *block7
);
#endif
#ifdef __AVX512F__
#ifdef __SHA__
/**
 * @brief Process eight independent 512-bit blocks in parallel using AVX-512 SHA extensions
 * @param state0..7 Eight 8-word state arrays (a-h) to update
 * @param block0..7 Eight pointers to 64-byte input blocks
 */
void sha256_process8_avx512(
    uint32_t state0[8], uint32_t state1[8], uint32_t state2[8], uint32_t state3[8],
    uint32_t state4[8], uint32_t state5[8], uint32_t state6[8], uint32_t state7[8],
    const uint8_t *block0, const uint8_t *block1, const uint8_t *block2, const uint8_t *block3,
    const uint8_t *block4, const uint8_t *block5, const uint8_t *block6, const uint8_t *block7
);
#endif /* __SHA__ */
#endif /* __AVX512F__ */
/**
 * @brief Compute N independent SHA-256 hashes of single-block messages in parallel.
 *
 * Auto-detects available CPU ISA, spawns one thread per core, and batches work
 * across threads for maximum throughput. Only SHA2_256 is supported; each
 * message must be exactly one 64-byte block. Outputs are 32-byte digests.
 *
 * @param type     Must be SHA2_256
 * @param data     Pointer to contiguous input buffer (n * SHA256_BLOCK_SIZE bytes)
 * @param digests  Pointer to contiguous output buffer (n * SHA256_DIGEST_SIZE bytes)
 * @param n        Number of messages
 * @return 0 on success, -1 on error
 */
int sha2_hash_parallel(sha2_hash_type type,
                       const void *data,
                       void *digests,
                       size_t n);

/**
 * @brief Compute N independent SHA-256 hashes of messages of uniform length with maximum throughput.
 *
 * Automatically selects the best available parallel path. Supports:
 *  - msg_len == SHA256_BLOCK_SIZE: multi-threaded single-block path using SHA-NI/SIMD.
 *  - msg_len <= SHA256_BLOCK_SIZE - 9: in-place single-block padding then parallel path.
 *  - otherwise: serial fallback to sha2_hash per message.
 *
 * @param type     Must be SHA2_256
 * @param data     Input buffer of n messages, each msg_len bytes.
 * @param msg_len  Length of each message in bytes.
 * @param digests  Output buffer of n digests (SHA256_DIGEST_SIZE bytes each).
 * @param n        Number of messages.
 * @return 0 on success, -1 on error
 */
int sha2_hash_many(sha2_hash_type type,
                   const void *data,
                   size_t msg_len,
                   void *digests,
                   size_t n);
#ifdef __cplusplus
}
#endif

#endif /* SHA2_H */
