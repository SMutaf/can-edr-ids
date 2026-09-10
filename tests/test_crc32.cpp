#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>

#include "edr/crc32.hpp"

using edr::crc32;
using edr::crc32_update;

namespace {
const uint8_t* bytes(const char* s) {
    return reinterpret_cast<const uint8_t*>(s);
}
}  // namespace

TEST_CASE("crc32 known test vector", "[crc32]") {
    REQUIRE(crc32(bytes("123456789"), 9) == 0xCBF43926u);
}

TEST_CASE("crc32 incremental matches one-shot", "[crc32]") {
    const std::string data = "The quick brown fox jumps over the lazy dog";

    uint32_t crc = 0xFFFFFFFFu;
    crc = crc32_update(crc, bytes(data.c_str()), 10);
    crc = crc32_update(crc, bytes(data.c_str()) + 10, 15);
    crc = crc32_update(crc, bytes(data.c_str()) + 25, data.size() - 25);
    crc ^= 0xFFFFFFFFu;

    REQUIRE(crc == crc32(bytes(data.c_str()), data.size()));
}

TEST_CASE("crc32 empty input is consistent", "[crc32]") {
    const uint32_t empty = crc32(nullptr, 0);
    REQUIRE(empty == 0x00000000u);
    REQUIRE(empty == (crc32_update(0xFFFFFFFFu, nullptr, 0) ^ 0xFFFFFFFFu));
}
