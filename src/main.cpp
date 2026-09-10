#include <array>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "edr/ids.hpp"
#include "edr/record.hpp"
#include "edr/recorder.hpp"
#include "edr/ring_buffer.hpp"
#include "edr/socket_can_source.hpp"

namespace {

using namespace edr;

// --- Tunables (see README) -------------------------------------------------
constexpr std::size_t RING_CAPACITY      = 2048;     // RecordEntry slots
constexpr uint64_t    ANOMALY_WINDOW_US  = 1000000;  // sliding window, 1 s
constexpr std::size_t ANOMALY_THRESHOLD  = 3;        // anomalies -> Attack
constexpr uint64_t    POST_TRIGGER_US    = 500000;   // 0.5 s after trigger
constexpr uint32_t    CRASH_CAN_ID       = 0x000;    // airbag-style trigger

// -------------------------------------------------------------------------

volatile std::sig_atomic_t g_running = 1;
void on_sigint(int) { g_running = 0; }

// Real-time clock in microseconds. Matches the kernel SO_TIMESTAMP domain
// so frame timestamps and timeout checks share one time base.
uint64_t now_us() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<microseconds>(system_clock::now().time_since_epoch())
            .count());
}

// Lowest set bit of an AnomalyFlag field: the first rule that fired.
uint8_t first_flag(uint8_t flags) {
    for (unsigned bit = 1; bit <= 0x80; bit <<= 1) {
        if (flags & bit) {
            return static_cast<uint8_t>(bit);
        }
    }
    return 0;
}

// Fixed-size sliding-window anomaly counter. No heap.
class AnomalyWindow {
public:
    // Record an anomaly at ts; true if the window is now saturated.
    bool add(uint64_t ts) {
        stamps_[head_] = ts;
        ++head_;
        if (head_ == ANOMALY_THRESHOLD) {
            head_ = 0;
        }
        if (filled_ < ANOMALY_THRESHOLD) {
            ++filled_;
        }

        const uint64_t cutoff =
            (ts > ANOMALY_WINDOW_US) ? ts - ANOMALY_WINDOW_US : 0;
        std::size_t in_window = 0;
        for (std::size_t i = 0; i < filled_; ++i) {
            if (stamps_[i] >= cutoff) {
                ++in_window;
            }
        }
        return in_window >= ANOMALY_THRESHOLD;
    }

    void clear() {
        stamps_.fill(0);
        head_ = 0;
        filled_ = 0;
    }

private:
    std::array<uint64_t, ANOMALY_THRESHOLD> stamps_{};
    std::size_t head_ = 0;
    std::size_t filled_ = 0;
};

std::string record_path(uint64_t stamp) {
    return "record_" + std::to_string(stamp) + ".edr";
}

}  // namespace

int main(int argc, char** argv) {
    const std::string ifname = (argc > 1) ? argv[1] : "vcan0";

    std::signal(SIGINT, on_sigint);
    std::signal(SIGTERM, on_sigint);

    SocketCanSource source(ifname);
    if (!source.is_open()) {
        std::cerr << "error: cannot open CAN interface '" << ifname << "'\n";
        return 1;
    }

    // Example profiles. A real deployment would load these from a DBC.
    Ids ids({
        {0x180, 8, 10000, 2000},
        {0x200, 2, 20000, 3000},
        {0x300, 4, 0, 0},
    });

    // Static: large buffer, kept off the stack, no heap.
    static RingBuffer<RecordEntry, RING_CAPACITY> buffer;

    AnomalyWindow window;

    bool recording = false;             // Attack post-trigger mode
    uint64_t post_deadline_us = 0;      // when to flush the record
    TriggerInfo pending_trigger{};      // trigger being collected for

    std::vector<RecordEntry> missing;

    while (g_running) {
        RecordEntry entry;
        const bool got = source.read(entry);
        const uint64_t now = got ? entry.timestamp_us : now_us();

        bool attack_trigger = false;
        uint8_t trigger_reason = 0;

        if (got) {
            if (entry.can_id == CRASH_CAN_ID) {
                // Crash trigger: push the crash frame so it shows up in
                // the record, then dump the pre-trigger window at once.
                // No post-trigger collection for a crash.
                entry.flags = 0;
                buffer.push(entry);
                const TriggerInfo trig{TriggerType::Crash, 0, now};
                const std::string path = record_path(now);
                const bool ok = write_record(path, buffer, trig);
                std::cerr << "TRIGGER: type=Crash reason=0 file=" << path
                          << (ok ? "" : " (WRITE FAILED)") << "\n";
            } else {
                entry.flags = ids.inspect(entry);
                buffer.push(entry);
                if (entry.flags != 0) {
                    std::cerr << "anomaly: can_id=0x" << std::hex << entry.can_id
                              << " flags=0x" << unsigned(entry.flags) << std::dec
                              << "\n";
                    if (window.add(now) && !recording) {
                        attack_trigger = true;
                        trigger_reason = first_flag(entry.flags);
                    }
                }
            }
        }

        // Run every iteration; the read timeout paces the loop.
        missing.clear();
        ids.check_timeouts(now, missing);
        for (const auto& m : missing) {
            buffer.push(m);
            std::cerr << "anomaly: can_id=0x" << std::hex << m.can_id
                      << " flags=0x" << unsigned(m.flags) << std::dec
                      << " (missing)\n";
            if (window.add(now) && !recording && !attack_trigger) {
                attack_trigger = true;
                trigger_reason = first_flag(m.flags);
            }
        }

        // Arm Attack post-trigger recording.
        if (attack_trigger && !recording) {
            recording = true;
            post_deadline_us = now + POST_TRIGGER_US;
            pending_trigger = TriggerInfo{TriggerType::Attack, trigger_reason, now};
            std::cerr << "TRIGGER: type=Attack reason=0x" << std::hex
                      << unsigned(trigger_reason) << std::dec << " collecting "
                      << POST_TRIGGER_US << " us of post-trigger data\n";
        }

        // Flush once enough time has passed; checked every loop iteration
        // so a silent bus still flushes (the clock keeps advancing).
        if (recording && now >= post_deadline_us) {
            const std::string path = record_path(pending_trigger.trigger_time_us);
            const bool ok = write_record(path, buffer, pending_trigger);
            std::cerr << "TRIGGER: type=Attack reason=0x" << std::hex
                      << unsigned(pending_trigger.reason) << std::dec
                      << " file=" << path << (ok ? "" : " (WRITE FAILED)")
                      << "\n";
            recording = false;
            window.clear();
        }
    }

    std::cerr << "shutting down\n";
    return 0;
}
