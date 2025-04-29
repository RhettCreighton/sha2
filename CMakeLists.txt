cmake_minimum_required(VERSION 3.12)
# Auto-load Clang toolchain for clang-18 / clang++-18 and lld-18
if(NOT DEFINED CMAKE_C_COMPILER OR CMAKE_C_COMPILER STREQUAL "")
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/clang-toolchain.cmake")
    message(STATUS "Auto-loading Clang toolchain (clang-toolchain.cmake)")
    include("${CMAKE_CURRENT_SOURCE_DIR}/clang-toolchain.cmake")
  endif()
endif()
project(sha2 VERSION 1.1.0 LANGUAGES C ASM)

# Global optimization flags (enable AVX2 macros for examples)
add_compile_options(-O3 -march=native -funroll-loops)
# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Library source files
set(SHA2_SOURCES
    src/sha2.c
    src/sha256.c
    src/sha256_shaext.c
    src/sha256_avx2.c
    src/sha512_avx2.c
    src/sha256_avx512.c
    src/sha512.c
    src/hash_function.c
    src/sha256_ni_transform.S
    src/sha512_avx512.c
)

# Create library (static by default)
add_library(sha2 ${SHA2_SOURCES})

# Set warning levels
target_compile_options(sha2 PRIVATE
    -Wall -Wextra -Wpedantic -Werror
)
## Performance optimizations: enable aggressive compile flags
target_compile_options(sha2 PRIVATE
    -O3
    -march=native
    -funroll-loops
    -fno-math-errno
)

# Optionally enable Link-Time Optimization (LTO) if supported
option(SHA2_ENABLE_LTO "Enable link-time optimization" ON)
# Disable LTO when building with Clang, to avoid bitcode archives that break direct ld linking
if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
  set(SHA2_ENABLE_LTO OFF CACHE BOOL "Disable LTO when using Clang" FORCE)
  message(STATUS "Disabling LTO for Clang builds to ensure compatibility with standard linkers")
endif()
## Profile-Guided Optimization (PGO)
option(SHA2_ENABLE_PGO "Enable profile-guided optimization" OFF)
if(SHA2_ENABLE_PGO)
    message(STATUS "Profile-Guided Optimization (PGO) enabled: instrumenting build")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-generate")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-generate")
endif()
if(SHA2_ENABLE_LTO)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT HAS_IPO)
    if(HAS_IPO)
        message(STATUS "Link-Time Optimization (LTO) enabled for sha2")
        set_property(TARGET sha2 PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
    else()
        message(STATUS "Link-Time Optimization (LTO) not supported by compiler")
    endif()
endif()

# Install headers
install(FILES include/sha2.h DESTINATION include)

# Install library
install(TARGETS sha2
        EXPORT sha2Targets
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin)

# Generate and install package files
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/sha2ConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/sha2Config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/sha2Config.cmake"
    @ONLY
)

install(
    FILES
        "${CMAKE_CURRENT_BINARY_DIR}/sha2Config.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/sha2ConfigVersion.cmake"
    DESTINATION lib/cmake/sha2
)

install(
    EXPORT sha2Targets
    FILE sha2Targets.cmake
    DESTINATION lib/cmake/sha2
)

# Enable testing and examples
option(SHA2_BUILD_TESTS "Build tests for SHA2 library" ON)
option(SHA2_BUILD_EXAMPLES "Build examples for SHA2 library" ON)

# Optional: tests
if(SHA2_BUILD_TESTS)
    # Enable testing
    enable_testing()
    
    # Add test executable
    add_executable(test_sha2 tests/test_sha2.c)
    target_link_libraries(test_sha2 sha2)
    
    # Add test
    add_test(NAME test_sha2 COMMAND test_sha2)
endif()

# Optional: examples (disabled by default now)
if(SHA2_BUILD_EXAMPLES)
    # Simple hash example
    add_executable(sha2_hash_example examples/hash_example.c)
    target_link_libraries(sha2_hash_example sha2)
    
    # Fiat-Shamir example with sumcheck protocol
    add_executable(sha2_fiat_shamir_example examples/fiat_shamir_example.c)
    target_link_libraries(sha2_fiat_shamir_example sha2)
    
    # Benchmark: measure SHA-256 hashes per second
    add_executable(sha2_benchmark examples/sha2_benchmark.c)
    target_link_libraries(sha2_benchmark sha2)
    # Benchmark: measure SHA-512 hashes per second
    add_executable(sha2_benchmark512 examples/sha2_benchmark512.c)
    target_link_libraries(sha2_benchmark512 sha2)
    
    # Copy executables to bin/
    set_target_properties(
        sha2_hash_example sha2_fiat_shamir_example sha2_benchmark sha2_benchmark512
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
endif()