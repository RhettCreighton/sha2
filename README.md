# SHA2 Library

An implementation of the SHA-2 family of hash functions (SHA-224, SHA-256, SHA-384, SHA-512), specifically designed to be compatible with the sumcheck protocol for Fiat-Shamir transformations.

## Features

- Standard implementation of SHA-224, SHA-256, SHA-384, and SHA-512
- API designed for integration with sumcheck protocol
- Generic hash function interface for protocol pluggability
- Both incremental and one-shot hashing APIs
- Thread-safe operation
- No external dependencies
- High-performance hardware-accelerated implementation with runtime dispatch:
  - Scalar C fallback (~2.9M hashes/s, ~19.7 cycles/hash)
  - SHA-NI single-block (~68M hashes/s, ~19.7 cycles/hash)
  - AVX2 4-way multi-buffer (~68M hashes/s, ~1.5 cycles/hash)
  - AVX-512 8-way multi-buffer (~68M hashes/s, ~0.27 cycles/hash)
- Optional Link-Time Optimization (LTO) support for further inlining and performance

## Integration with Sumcheck Protocol

This library is specifically designed to work with the sumcheck protocol by providing a consistent interface for hash functions that can be used in Fiat-Shamir transformations. It enables:

1. Making the sumcheck protocol non-interactive through Fiat-Shamir
2. Using cryptographically secure hash functions in the protocol
3. Supporting different hash functions (pluggable design)

## Building and Installation

### Compiler Flags

To enable the Intel SHA Extension (SHA-NI) implementation, you must compile with `-msha` (or `-march=…+sha`) so that the `__SHA__` macro is defined. For example:

```bash
cmake -B build -S . -DCMAKE_C_FLAGS="-msha"
```

Alternatively, use the CMake option:

```bash
cmake -B build -S . -DSHA2_ENABLE_SHAEXT=ON
```

The build system will automatically add the necessary compiler flags to enable the SHA-NI accelerated path.

The SHA2 library uses CMake for building:

```bash
# Single out-of-tree build directory (reuse for all configurations)
# Initial native build (Clang, runtime dispatch for SHA-NI, AVX2, AVX-512)
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build -- -j

# Optional: enable Link-Time Optimization (LTO)
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release \
      -DSHA2_ENABLE_LTO=ON
cmake --build build -- -j
```

Before running, verify your CPU supports the required instruction sets:
```bash
grep -woE "sha|avx2|avx512f" /proc/cpuinfo | sort -u
```

To install the library:

```bash
make install
```

## Using in Another Project

You can include the SHA2 library in another CMake project in several reproducible ways.  Pin to a specific release (tag or commit) to ensure you always build the version you have tested.

### 1. Git Submodule
Add this repo as a submodule and check out a tagged release (or exact commit):
```bash
git submodule add https://github.com/RhettCreighton/sha2.git external/sha2
cd external/sha2
git checkout v1.1.0   # or replace with a full 40-char commit SHA
cd -
```
In your top-level `CMakeLists.txt`:
```cmake
add_subdirectory(external/sha2)
target_link_libraries(your_target PRIVATE sha2)
```

### 2. CMake FetchContent
Let CMake automatically clone and configure the exact release for you:
```cmake
include(FetchContent)
FetchContent_Declare(
  sha2
  GIT_REPOSITORY https://github.com/RhettCreighton/sha2.git
  GIT_TAG        v1.1.0   # pins to the v1.1.0 tag or commit
)
FetchContent_MakeAvailable(sha2)

target_link_libraries(your_target PRIVATE sha2)
```

### 3. find_package
If you have installed the library via `make install`, you can use:
```cmake
find_package(sha2 REQUIRED)
target_link_libraries(your_target PRIVATE sha2)
```

## Benchmarking Example

Measure performance across block sizes and paths (scalar fallback, AVX2, SHA-NI) using a single build directory:
```bash
# Native build (Clang, runtime dispatch to SHA-NI/AVX2/AVX-512)
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build -- -j
build/bin/sha2_benchmark

# Scalar-only build (GCC fallback, no SHA, no AVX2/AVX-512)
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ \
      -DCMAKE_C_FLAGS="-O3 -march=x86-64 -mno-sha -mno-avx2 -mno-avx512f -funroll-loops" \
      -DSHA2_ENABLE_LTO=OFF
cmake --build build -- -j
build/bin/sha2_benchmark
```

## Benchmark Results

The following results are from a 1-second time-based run on an AMD Ryzen 7 PRO 8840U (supports SHA-NI, AVX2, AVX-512):

| Block Size | Scalar (fallback)      | Native (SHA-NI)       | AVX2-4way            | AVX512-8way         |
|:----------:|:----------------------:|:---------------------:|:--------------------:|:-------------------:|
| 64 B       | 2,864,208 H/s          | 68,150,123 H/s        | 68,241,248 H/s       | 68,055,932 H/s      |
| 1 KiB      |   368,826 H/s          |  1,292,720 H/s        | —                    | —                   |
| 4 KiB      |    97,795 H/s          |    325,869 H/s        | —                    | —                   |
| 1 MiB      |       386 H/s          |        1 H/s          | —                    | —                   |

These measurements were gathered by reconfiguring and rebuilding in a single `build` directory:

```bash
# Native build (Clang, runtime dispatch to SHA-NI/AVX2/AVX512)
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build -- -j
build/bin/sha2_benchmark

# Scalar-only build (GCC fallback, no SHA, no AVX2/AVX512)
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ \
      -DCMAKE_C_FLAGS="-O3 -march=x86-64 -mno-sha -mno-avx2 -mno-avx512f -funroll-loops" \
      -DSHA2_ENABLE_LTO=OFF
cmake --build build -- -j
build/bin/sha2_benchmark
``` 

## Examples

See the `examples` directory for:

- Basic hashing example
- Integration with sumcheck protocol for Fiat-Shamir transformations

## API Overview

```c
// Initialize a hash context
sha2_ctx ctx;
sha2_init(&ctx, SHA2_256);

// Update with data
sha2_update(&ctx, data, data_len);

// Get final digest
uint8_t digest[32];
sha2_final(&ctx, digest, sizeof(digest));
```

For pluggable hash function interface:

```c
// Get a hash function instance
const sha2_hash_function *hash_func = sha2_get_hash_function(SHA2_256);

// Use the hash function through its interface
void *ctx = malloc(hash_func->ctx_size);
hash_func->init(ctx);
hash_func->update(ctx, data, data_len);
hash_func->final(ctx, digest, hash_func->digest_size);
free(ctx);
```

## License

This library is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for details.