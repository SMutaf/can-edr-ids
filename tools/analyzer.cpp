// EDR record analyzer: decode a binary .edr file, verify it, and print a
// human-readable report. The inverse of the recorder.

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

#include "edr/crc32.hpp"
#include "edr/record.hpp"

namespace {

using namespace edr;

const char* trigger_type_str(uint8_t t) {
    switch (static_cast<TriggerType>(t)) {
        case TriggerType::Crash:
            return "Crash";
        case TriggerType::Attack:
            return "Attack";
    }
    return "Unknown";
}

struct FlagDef {
    AnomalyFlag flag;
    const char* name;
};

constexpr FlagDef kFlagDefs[] = {
    {AnomalyFlag::PeriodViolation, "PeriodViolation"},
    {AnomalyFlag::MessageMissing, "MessageMissing"},
    {AnomalyFlag::UnknownId, "UnknownId"},
    {AnomalyFlag::InvalidDlc, "InvalidDlc"},
    {AnomalyFlag::RangeViolation, "RangeViolation"},
};

// "PeriodViolation|InvalidDlc", or "-" when no bits are set.
std::string flags_to_str(uint8_t flags) {
    if (flags == 0) {
        return "-";
    }
    std::string out;
    for (const auto& d : kFlagDefs) {
        if (flags & static_cast<uint8_t>(d.flag)) {
            if (!out.empty()) {
                out += '|';
            }
            out += d.name;
        }
    }
    return out;
}

// Frame time relative to the first frame, as "+X.XXX ms".
std::string rel_ms(uint64_t ts, uint64_t base) {
    const long long delta =
        static_cast<long long>(ts) - static_cast<long long>(base);
    std::ostringstream os;
    os << std::showpos << std::fixed << std::setprecision(3)
       << (static_cast<double>(delta) / 1000.0) << " ms";
    return os.str();
}

std::string data_hex(const RecordEntry& e) {
    const uint8_t n = (e.dlc > 8) ? 8 : e.dlc;
    std::ostringstream os;
    os << std::hex << std::uppercase << std::setfill('0');
    for (uint8_t i = 0; i < n; ++i) {
        if (i != 0) {
            os << ' ';
        }
        os << std::setw(2) << static_cast<int>(e.data[i]);
    }
    return os.str();
}

void print_frame(const RecordEntry& e, uint64_t base) {
    std::ostringstream id;
    id << "0x" << std::hex << std::uppercase << std::setw(3) << std::setfill('0')
       << e.can_id;

    std::cout << "  " << std::left << std::setw(13) << rel_ms(e.timestamp_us, base)
              << ' ' << std::setw(7) << id.str() << " [" << static_cast<int>(e.dlc)
              << "]  " << std::setw(23) << data_hex(e) << std::right;
    if (e.flags != 0) {
        std::cout << "  ! " << flags_to_str(e.flags);
    }
    std::cout << "\n";
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <file.edr> [--full]\n";
        return 1;
    }

    const std::string path = argv[1];
    bool full = false;
    for (int i = 2; i < argc; ++i) {
        if (std::string(argv[i]) == "--full") {
            full = true;
        }
    }

    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cerr << "error: cannot open '" << path << "'\n";
        return 1;
    }
    const std::vector<uint8_t> buf((std::istreambuf_iterator<char>(in)),
                                   std::istreambuf_iterator<char>());

    if (buf.size() < sizeof(FileHeader)) {
        std::cerr << "error: file too short for a header\n";
        return 1;
    }

    FileHeader h{};
    std::memcpy(&h, buf.data(), sizeof(h));

    if (h.magic != kFileMagic) {
        std::cerr << "error: not an EDR file (bad magic)\n";
        return 1;
    }
    if (h.version != 1) {
        std::cerr << "warning: unexpected version " << h.version
                  << " (expected 1); continuing\n";
    }
    if (h.entry_size != sizeof(RecordEntry)) {
        std::cerr << "warning: entry_size " << h.entry_size
                  << " != sizeof(RecordEntry) " << sizeof(RecordEntry)
                  << "; continuing\n";
    }

    const std::size_t need = sizeof(FileHeader) +
                             static_cast<std::size_t>(h.entry_count) *
                                 sizeof(RecordEntry) +
                             sizeof(uint32_t);
    if (buf.size() < need) {
        std::cerr << "error: file too short: need " << need << " bytes, have "
                  << buf.size() << "\n";
        return 1;
    }

    std::vector<RecordEntry> entries(h.entry_count);
    for (uint16_t i = 0; i < h.entry_count; ++i) {
        std::memcpy(&entries[i],
                    buf.data() + sizeof(FileHeader) + i * sizeof(RecordEntry),
                    sizeof(RecordEntry));
    }

    uint32_t stored_crc = 0;
    std::memcpy(&stored_crc,
                buf.data() + sizeof(FileHeader) +
                    static_cast<std::size_t>(h.entry_count) * sizeof(RecordEntry),
                sizeof(stored_crc));

    // Recompute exactly as the recorder did: seed, fold header + entries,
    // final XOR.
    uint32_t crc = 0xFFFFFFFFu;
    crc = crc32_update(crc, buf.data(), sizeof(FileHeader));
    crc = crc32_update(
        crc, buf.data() + sizeof(FileHeader),
        static_cast<std::size_t>(h.entry_count) * sizeof(RecordEntry));
    crc ^= 0xFFFFFFFFu;
    const bool crc_ok = (crc == stored_crc);

    const uint64_t base =
        entries.empty() ? 0 : entries.front().timestamp_us;

    std::cout << "=== EDR Record: " << path << " ===\n";
    std::cout << "Trigger:  " << trigger_type_str(h.trigger_type) << " ("
              << flags_to_str(h.trigger_reason) << ")\n";
    std::cout << "Time:     " << h.trigger_time_us << " us\n";
    std::cout << "Frames:   " << h.entry_count << "\n";
    std::cout << "CRC:      " << (crc_ok ? "OK" : "MISMATCH") << "\n";
    if (!crc_ok) {
        std::cout << "          WARNING: data may be unreliable\n";
    }

    std::size_t counts[5] = {0, 0, 0, 0, 0};
    for (const auto& e : entries) {
        for (std::size_t k = 0; k < 5; ++k) {
            if (e.flags & static_cast<uint8_t>(kFlagDefs[k].flag)) {
                ++counts[k];
            }
        }
    }

    std::cout << "\nAnomaly summary:\n";
    bool any_counted = false;
    for (std::size_t k = 0; k < 5; ++k) {
        if (counts[k] > 0) {
            std::cout << "  " << std::left << std::setw(18)
                      << (std::string(kFlagDefs[k].name) + ":") << counts[k]
                      << "\n";
            any_counted = true;
        }
    }
    if (!any_counted) {
        std::cout << "  none\n";
    }

    std::cout << "\nAnomalous frames:\n";
    bool any_anom = false;
    for (const auto& e : entries) {
        if (e.flags != 0) {
            print_frame(e, base);
            any_anom = true;
        }
    }
    if (!any_anom) {
        std::cout << "  none\n";
    }

    if (full) {
        std::cout << "\nTimeline:\n";
        for (const auto& e : entries) {
            print_frame(e, base);
        }
    }

    return 0;
}
