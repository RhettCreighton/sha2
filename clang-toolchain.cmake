 # clang-toolchain.cmake
 # Toolchain file to force Clang 18 (clang-18 / clang++-18) and LLD 18

 # Detect clang-18 and clang++-18
find_program(CLANG_C_BIN NAMES clang-18 clang)
find_program(CLANG_CXX_BIN NAMES clang++-18 clang++)
if(CLANG_C_BIN AND CLANG_CXX_BIN)
  # Use Clang 18 for compiling
  set(CMAKE_C_COMPILER ${CLANG_C_BIN} CACHE FILEPATH "C compiler" FORCE)
  set(CMAKE_CXX_COMPILER ${CLANG_CXX_BIN} CACHE FILEPATH "C++ compiler" FORCE)
  # Force linker driver to Clang 18 as well
  set(CMAKE_LINKER ${CLANG_C_BIN} CACHE FILEPATH "Linker" FORCE)
endif()

# Detect LLD linker (prefer lld-18)
find_program(LLD_BIN NAMES lld-18 lld)
if(LLD_BIN AND CMAKE_C_COMPILER_ID STREQUAL "Clang")
  # Use LLD for better linking performance under Clang
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fuse-ld=${LLD_BIN}" CACHE STRING "C flags" FORCE)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fuse-ld=${LLD_BIN}" CACHE STRING "CXX flags" FORCE)
  message(STATUS "Using LLD (via -fuse-ld=${LLD_BIN}) for Clang link")
endif()