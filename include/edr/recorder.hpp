#ifndef EDR_RECORDER_HPP
#define EDR_RECORDER_HPP

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>

#include "edr/crc32.hpp"
#include "edr/record.hpp"
#include "edr/ring_buffer.hpp"

namespace edr {

// What fired the recorder, forwarded into the file header.
struct TriggerInfo {
    TriggerType type;
    uint8_t     reason;  // AnomalyFlag, 0 for Crash
    uint64_t    trigger_time_us;
};

// Dump a ring buffer snapshot to disk: FileHeader, then every entry
// oldest-to-newest, then a trailing CRC-32 over header + entries.
// Stateless; no post-trigger logic. Returns false on any I/O failure.
template <std::size_t N>
bool write_record(const std::string& path,
                  const RingBuffer<RecordEntry, N>& buffer,
                  const TriggerInfo& trigger) {
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        return false;
    }

    FileHeader header;
    std::memset(&header, 0, sizeof(header));
    header.magic = kFileMagic;
    header.version = 1;
    header.entry_size = static_cast<uint16_t>(sizeof(RecordEntry));
    header.trigger_time_us = trigger.trigger_time_us;
    header.trigger_type = static_cast<uint8_t>(trigger.type);
    header.trigger_reason = trigger.reason;
    header.entry_count = static_cast<uint16_t>(buffer.size());

    uint32_t crc = 0xFFFFFFFFu;

    out.write(reinterpret_cast<const char*>(&header), sizeof(header));
    crc = crc32_update(crc, reinterpret_cast<const uint8_t*>(&header),
                       sizeof(header));

    buffer.for_each([&](const RecordEntry& entry) {
        out.write(reinterpret_cast<const char*>(&entry), sizeof(entry));
        crc = crc32_update(crc, reinterpret_cast<const uint8_t*>(&entry),
                           sizeof(entry));
    });

    crc ^= 0xFFFFFFFFu;
    out.write(reinterpret_cast<const char*>(&crc), sizeof(crc));

    out.close();
    return static_cast<bool>(out);
}

// Frozen-snapshot variant: 'pre' is the pre-trigger window captured at
// trigger time, 'post' the frames collected afterwards. Written as one
// stream, pre first then post, so the attack onset can never be
// overwritten by later traffic. Same file layout and trailing CRC.
template <std::size_t NPre, std::size_t NPost>
bool write_record(const std::string& path,
                  const RingBuffer<RecordEntry, NPre>& pre,
                  const RingBuffer<RecordEntry, NPost>& post,
                  const TriggerInfo& trigger) {
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        return false;
    }

    FileHeader header;
    std::memset(&header, 0, sizeof(header));
    header.magic = kFileMagic;
    header.version = 1;
    header.entry_size = static_cast<uint16_t>(sizeof(RecordEntry));
    header.trigger_time_us = trigger.trigger_time_us;
    header.trigger_type = static_cast<uint8_t>(trigger.type);
    header.trigger_reason = trigger.reason;
    header.entry_count = static_cast<uint16_t>(pre.size() + post.size());

    uint32_t crc = 0xFFFFFFFFu;

    out.write(reinterpret_cast<const char*>(&header), sizeof(header));
    crc = crc32_update(crc, reinterpret_cast<const uint8_t*>(&header),
                       sizeof(header));

    const auto write_entry = [&](const RecordEntry& entry) {
        out.write(reinterpret_cast<const char*>(&entry), sizeof(entry));
        crc = crc32_update(crc, reinterpret_cast<const uint8_t*>(&entry),
                           sizeof(entry));
    };
    pre.for_each(write_entry);
    post.for_each(write_entry);

    crc ^= 0xFFFFFFFFu;
    out.write(reinterpret_cast<const char*>(&crc), sizeof(crc));

    out.close();
    return static_cast<bool>(out);
}

}  // namespace edr

#endif  // EDR_RECORDER_HPP
