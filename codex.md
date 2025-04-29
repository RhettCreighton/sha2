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
     cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
     cmake --build build -- -j
     build/bin/sha2_benchmark
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
   - AMD Ryzen 7 PRO 8840U (1-second run, 64-byte blocks):
     * Scalar fallback: ~2.9M H/s
     * SHA-NI: ~68M H/s
     * AVX2-4way: ~68M H/s
     * AVX512-8way: ~68M H/s

6. Integration Options
   - Git submodule, CMake FetchContent, or `find_package(sha2)` after installation.
   - Pin to version `1.1.0` via tag or commit SHA for reproducibility.

Always clean up temporary build artifacts (`build/`) before committing.