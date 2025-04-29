SHA2 Library Assistant Codex
===========================

This file provides essential context and guidelines for AI coding assistants working with the SHA2 library.

## Technical Overview
The SHA2 library implements the entire SHA-2 family in portable C with optional hardware-accelerated paths.
At its core, each variant (SHA-224, SHA-256, SHA-384, SHA-512) is built on a message schedule (γ₀/γ₁ functions) and a round function
that updates eight working variables (a–h) with bitwise operations (`ch`, `maj`) and addition by round constants (K).

To maximize performance on modern x86 CPUs, the library provides multiple dispatchable paths:
- **Scalar C fallback** (pure C, no extensions) for portability (~2.9M hashes/sec on Ryzen 7 PRO 8840U).
- **SHA-NI single-block** assembler (`sha256_ni_transform.S`) for the SHA extensions ISA (~68M hashes/sec).
- **AVX2 4-way parallel** (`sha256_avx2.c` / `sha512_avx2.c`) using 256-bit vector registers (~68M hashes/sec, ~1.5 cycles/hash).
- **AVX-512 8-way parallel** (`sha256_avx512.c` / `sha512_avx512.c`) using 512-bit EVEX intrinsics (~68M hashes/sec, ~0.27 cycles/hash).

By layering these paths under a unified API and runtime-checking CPU features (`__builtin_cpu_supports`),
the library delivers both broad compatibility and world-class throughput for diverse workloads.

1. Project Layout
   - Top-level: CMakeLists.txt, README.md, codex.md
   - include/: public headers (sha2.h)
   - src/: core implementations (sha2.c, sha256.c, sha512.c), SIMD/ASM accelerations
   - examples/: demonstration programs and benchmarks
   - tests/: unit tests (test_sha2.c)

2. Build & Test Workflow
   - Use a single out-of-tree `build/` directory for all configurations:
     ```bash
     cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug
     cmake --build build -- -j && ctest --output-on-failure
     ```
   - For release/benchmark:
     ```bash
     # Wipe and recreate a single build directory
     rm -rf build build_*        # remove any stale builds
     cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
     cmake --build build -- -j
     ```
     ```bash
     # Run the full-core small-message saturation benchmark
     build/bin/sha2_benchmark_many    # one-build, one-run for peak MH/s
     ```

3. Coding Guidelines
   - Focus on root-cause fixes; avoid superficial patches.
   - Follow existing style: 2-space indent, minimal inline comments.
   - Use `apply_patch` for all modifications.
   - Update documentation (README.md, comments) alongside code changes.
   - Ensure public APIs remain consistent unless version bump.

4. SIMD & Assembly Paths
   - The code includes optional accelerated paths:
     * SHA-NI (`__SHA__`) single-block in sha256_ni_transform.S
     * AVX2 4-way in sha256_avx2.c / sha512_avx2.c
     * AVX-512 8-way in sha256_avx512.c / sha512_avx512.c
   - Runtime dispatch is managed by `__builtin_cpu_supports` checks.

5. Benchmarks Summary
   - Many small messages (e.g., 55 B) via `sha2_benchmark_many`: ~385M H/s total on 16 cores

6. Integration Options
   - Git submodule, CMake FetchContent, or `find_package(sha2)` after installation.
   - Pin to version `1.1.0` via tag or commit SHA for reproducibility.

Clean up temporary build artifacts before committing:
```bash
# Remove all build artifacts and untracked files (use with care)
git clean -fdx
```
## Public API: sha2_hash_many
The `sha2_hash_many` function provides a simple high-performance interface to compute `n` SHA-256 hashes of uniform-length messages:
  - Prototype: `int sha2_hash_many(sha2_hash_type type, const void *data, size_t msg_len, void *digests, size_t n);`
  - If `msg_len == SHA256_BLOCK_SIZE`, it uses the multi-threaded single-block parallel path (`sha2_hash_parallel`).
  - If `msg_len <= SHA256_BLOCK_SIZE - 9`, messages are padded in-place to 64 bytes and then dispatched in parallel.
  - Otherwise, falls back to serial `sha2_hash` per message.

Use this API for high-throughput hashing of many small messages without manual padding or threading.