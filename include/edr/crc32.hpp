#ifndef EDR_CRC32_HPP
#define EDR_CRC32_HPP

#include <cstddef>
#include <cstdint>

namespace edr {

// CRC-32 (IEEE 802.3 / zlib variant): poly 0xEDB88320 reflected,
// init 0xFFFFFFFF, final XOR 0xFFFFFFFF, reflected in and out.

// Fold more bytes into a running CRC. Seed the first call with
// 0xFFFFFFFF; do not apply the final XOR between chunks.
uint32_t crc32_update(uint32_t crc, const uint8_t* data, std::size_t len);

// One-shot helper: seeds, folds, and applies the final XOR.
// crc32("123456789", 9) == 0xCBF43926.
uint32_t crc32(const uint8_t* data, std::size_t len);

}  // namespace edr

#endif  // EDR_CRC32_HPP
