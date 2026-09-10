include(FetchContent)

FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.5.2)
FetchContent_MakeAvailable(Catch2)

add_executable(edr_tests
    test_crc32.cpp
    test_ring_buffer.cpp
    test_ids.cpp
    test_recorder.cpp)
target_link_libraries(edr_tests PRIVATE edr_core Catch2::Catch2WithMain)

list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
include(Catch)
catch_discover_tests(edr_tests)
