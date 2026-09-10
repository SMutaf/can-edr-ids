#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "edr/crc32.hpp"
#include "edr/record.hpp"
#include "edr/recorder.hpp"
#include "edr/ring_buffer.hpp"

using edr::FileHeader;
using edr::kFileMagic;
using edr::RecordEntry;
using edr::RingBuffer;
using edr::TriggerInfo;
using edr::TriggerType;

namespace {

std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

RecordEntry frame(uint32_t id, uint64_t ts, uint8_t d0) {
    RecordEntry e{};
    e.can_id = id;
    e.timestamp_us = ts;
    e.dlc = 2;
    e.data[0] = d0;
    return e;
}

}  // namespace

TEST_CASE("write_record produces a well-formed file", "[recorder]") {
    RingBuffer<RecordEntry, 8> rb;
    for (uint32_t i = 0; i < 5; ++i) {
        rb.push(frame(0x100 + i, 1000 + i, static_cast<uint8_t>(i)));
    }

    const TriggerInfo trig{TriggerType::Attack, 0x02, 424242};
    const std::string path = "test_out.edr";
    REQUIRE(edr::write_record(path, rb, trig));

    std::vector<uint8_t> bytes = read_file(path);

    const std::size_t expected =
        sizeof(FileHeader) + 5 * sizeof(RecordEntry) + sizeof(uint32_t);
    REQUIRE(bytes.size() == expected);

    FileHeader header{};
    std::memcpy(&header, bytes.data(), sizeof(header));
    REQUIRE(header.magic == kFileMagic);
    REQUIRE(header.version == 1);
    REQUIRE(header.entry_size == sizeof(RecordEntry));
    REQUIRE(header.entry_count == 5);
    REQUIRE(header.trigger_type == static_cast<uint8_t>(TriggerType::Attack));
    REQUIRE(header.trigger_reason == 0x02);
    REQUIRE(header.trigger_time_us == 424242);

    SECTION("entries are stored oldest to newest") {
        for (uint32_t i = 0; i < 5; ++i) {
            RecordEntry e{};
            std::memcpy(&e, bytes.data() + sizeof(FileHeader) + i * sizeof(e),
                        sizeof(e));
            REQUIRE(e.can_id == 0x100 + i);
            REQUIRE(e.timestamp_us == 1000 + i);
            REQUIRE(e.data[0] == i);
        }
    }

    SECTION("stored crc matches a recomputed crc") {
        uint32_t stored = 0;
        std::memcpy(&stored, bytes.data() + bytes.size() - sizeof(stored),
                    sizeof(stored));
        const uint32_t calc =
            edr::crc32(bytes.data(), bytes.size() - sizeof(stored));
        REQUIRE(stored == calc);
    }

    SECTION("a flipped byte breaks the crc") {
        uint32_t stored = 0;
        std::memcpy(&stored, bytes.data() + bytes.size() - sizeof(stored),
                    sizeof(stored));
        bytes[sizeof(FileHeader) + 3] ^= 0x01;  // corrupt one payload byte
        const uint32_t calc =
            edr::crc32(bytes.data(), bytes.size() - sizeof(stored));
        REQUIRE(stored != calc);
    }

    std::remove(path.c_str());
}

TEST_CASE("write_record after overwrite keeps only the last N", "[recorder]") {
    RingBuffer<RecordEntry, 3> rb;
    for (uint32_t i = 0; i < 6; ++i) {
        rb.push(frame(0x200 + i, 5000 + i, 0));
    }

    const TriggerInfo trig{TriggerType::Crash, 0, 111};
    const std::string path = "test_out_overwrite.edr";
    REQUIRE(edr::write_record(path, rb, trig));

    std::vector<uint8_t> bytes = read_file(path);
    FileHeader header{};
    std::memcpy(&header, bytes.data(), sizeof(header));
    REQUIRE(header.entry_count == 3);
    REQUIRE(header.trigger_type == static_cast<uint8_t>(TriggerType::Crash));

    RecordEntry first{};
    std::memcpy(&first, bytes.data() + sizeof(FileHeader), sizeof(first));
    REQUIRE(first.can_id == 0x203);  // 0x200..0x202 were overwritten

    std::remove(path.c_str());
}
