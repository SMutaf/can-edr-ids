#ifndef EDR_RECORD_HPP
#define EDR_RECORD_HPP

#include <cstddef>
#include <cstdint>

namespace edr {

// What caused the recorder to freeze its buffer.
enum class TriggerType : uint8_t {
    Crash,  // airbag / impact style event: pre-trigger data only
    Attack  // IDS alarm: pre- and post-trigger data
};

// Per-frame anomaly markers. Bit field so several rules can fire at once.
enum class AnomalyFlag : uint8_t {
    None            = 0,
    PeriodViolation = 1 << 0,  // cycle time out of bounds
    MessageMissing  = 1 << 1,  // expected message did not arrive
    UnknownId       = 1 << 2,  // CAN ID not in the known set
    InvalidDlc      = 1 << 3,  // DLC does not match the spec
    RangeViolation  = 1 << 4   // signal value out of range (phase B)
};

#pragma pack(push, 1)

// One recorded CAN frame.
struct RecordEntry {
    uint64_t timestamp_us;  // kernel timestamp in microseconds
    uint32_t can_id;        // raw can_id, flag bits included
    uint8_t  dlc;           // 0-8
    uint8_t  data[8];       // only the first dlc bytes are meaningful
    uint8_t  flags;         // AnomalyFlag bit field
};

// File header written before the record stream.
struct FileHeader {
    uint32_t magic;            // fixed signature ("EDR\0")
    uint16_t version;          // format version, 1
    uint16_t entry_size;       // sizeof(RecordEntry)
    uint64_t trigger_time_us;  // time the trigger fired
    uint8_t  trigger_type;     // TriggerType value
    uint8_t  trigger_reason;   // AnomalyFlag that fired (0 for Crash)
    uint16_t entry_count;      // number of records that follow
};

#pragma pack(pop)

// Signature bytes 'E' 'D' 'R' '\0'.
constexpr uint32_t kFileMagic = 0x45445200;

static_assert(sizeof(RecordEntry) == 22, "RecordEntry must be packed with no padding");
static_assert(sizeof(FileHeader) == 20, "FileHeader must be packed with no padding");

}  // namespace edr

#endif  // EDR_RECORD_HPP
