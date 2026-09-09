#include "edr/crc32.hpp"

#include <array>

namespace edr {
namespace {

// 256-entry lookup table, built once at first use.
std::array<uint32_t, 256> make_table() {
    std::array<uint32_t, 256> table{};
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int k = 0; k < 8; ++k) {
            c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
        table[i] = c;
    }
    return table;
}

const std::array<uint32_t, 256>& table() {
    static const std::array<uint32_t, 256> t = make_table();
    return t;
}

}  // namespace

uint32_t crc32_update(uint32_t crc, const uint8_t* data, std::size_t len) {
    const auto& t = table();
    for (std::size_t i = 0; i < len; ++i) {
        crc = t[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    }
    return crc;
}

uint32_t crc32(const uint8_t* data, std::size_t len) {
    return crc32_update(0xFFFFFFFFu, data, len) ^ 0xFFFFFFFFu;
}

}  // namespace edr
