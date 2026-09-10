cmake_minimum_required(VERSION 3.15)
project(can_edr_ids CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Shared code. Linux-specific (linux/can.h); this project targets Linux.
add_library(edr_core STATIC
    src/crc32.cpp
    src/ids.cpp
    src/socket_can_source.cpp)
target_include_directories(edr_core PUBLIC include)

# Main capture loop.
add_executable(edr src/main.cpp)
target_link_libraries(edr PRIVATE edr_core)

# Tests: opt-in, and only if tests/ actually has a build file yet.
option(BUILD_TESTING "Build tests" ON)
if(BUILD_TESTING AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt")
    enable_testing()
    add_subdirectory(tests)
endif()

# tools/ — standalone helpers. attacker has its own socket code and does
# not need edr_core; analyzer added later.
add_executable(attacker tools/attacker.cpp)
