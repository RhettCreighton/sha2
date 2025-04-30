cmake_minimum_required(VERSION 3.12)
# Auto-load Clang toolchain for clang-18 / clang++-18 and lld-18
if(NOT DEFINED CMAKE_C_COMPILER OR CMAKE_C_COMPILER STREQUAL "")
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/clang-toolchain.cmake")
    message(STATUS "Auto-loading Clang toolchain (clang-toolchain.cmake)")
    include("${CMAKE_CURRENT_SOURCE_DIR}/clang-toolchain.cmake")
  endif()
endif()
project(sha2 VERSION 1.1.0 LANGUAGES C ASM)
find_package(Threads REQUIRED)

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
    src/sha2_parallel.c
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
# Optionally enable Intel SHA Extensions (SHA-NI) implementation
option(SHA2_ENABLE_SHAEXT "Enable Intel SHA Extensions (SHA-NI) implementation" ON)
include(CheckCSourceCompiles)

# Check if __SHA__ macro is defined by default
check_c_source_compiles("\
#ifdef __SHA__\
int main(void) { return 0; }\
#endif\
" SHA2_HAS_SHA_NI)

if(SHA2_ENABLE_SHAEXT)
  if(NOT SHA2_HAS_SHA_NI)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
      message(STATUS "SHA2_ENABLE_SHAEXT=ON: adding -msha to compiler flags to enable SHA-NI")
      target_compile_options(sha2 PRIVATE -msha)
      # Re-check with -msha flag
      set(CMAKE_REQUIRED_FLAGS "-msha")
      check_c_source_compiles("\
#ifdef __SHA__\
int main(void) { return 0; }\
#endif\
" SHA2_HAS_SHA_NI)
      unset(CMAKE_REQUIRED_FLAGS)
      if(NOT SHA2_HAS_SHA_NI)
        message(WARNING "Compiler does not support SHA Extensions (-msha) or __SHA__ still not defined; Intel SHA-NI unavailable")
      endif()
    else()
      message(WARNING "SHA2_ENABLE_SHAEXT=ON, but compiler ${CMAKE_C_COMPILER_ID} may not support -msha; Intel SHA-NI unavailable")
    endif()
  # Force compile-time dispatch for SHA-NI paths when SHAEXT is enabled
  target_compile_definitions(sha2 PRIVATE __SHA__)
  else()
    message(STATUS "Intel SHA Extensions available: __SHA__ is defined by default")
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
      message(STATUS "Adding -msha to compiler flags to ensure __SHA__ is defined")
      target_compile_options(sha2 PRIVATE -msha)
    endif()
  endif()
else()
  message(STATUS "Intel SHA Extensions disabled by SHA2_ENABLE_SHAEXT option")
endif()

# Warn if __SHA__ is not defined
if(NOT SHA2_HAS_SHA_NI)
  message(STATUS "Intel SHA Extensions not detected: pass -msha or enable SHA2_ENABLE_SHAEXT to enable SHA-NI optimizations")
endif()

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

    # Application example: batch API for small messages (≤55 bytes)
    add_executable(sha2_app_small_batch examples/sha2_app_small_batch.c)
    target_link_libraries(sha2_app_small_batch PRIVATE sha2 Threads::Threads)
    set_target_properties(sha2_app_small_batch PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
    # Friendly API example: peak throughput via sha256_hash_many()
    add_executable(sha2_app_fast_api examples/sha2_app_fast_api.c)
    target_link_libraries(sha2_app_fast_api PRIVATE sha2 Threads::Threads)
    set_target_properties(sha2_app_fast_api PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
endif()