#ifndef EDR_IDS_HPP
#define EDR_IDS_HPP

#include <cstdint>
#include <unordered_map>
#include <vector>

#include "edr/record.hpp"

namespace edr {

// Expectation profile for one known ID (would come from a DBC).
struct MessageProfile {
    uint32_t can_id;
    uint8_t  expected_dlc;   // expected payload length
    uint32_t period_us;      // expected period; 0 = not periodic
    uint32_t tolerance_us;   // allowed deviation
};

// Phase A behaviour-based intrusion detection. Without message
// authentication we infer anomalies from behaviour: unknown IDs, wrong
// length, timing violations.
class Ids {
public:
    explicit Ids(std::vector<MessageProfile> profiles);

    // Inspect one frame. Returns anomaly flags (AnomalyFlag bit field,
    // 0 = clean) for the caller to store in RecordEntry.flags. Also
    // updates this ID's last-seen time and clears any missing state.
    uint8_t inspect(const RecordEntry& entry);

    // Timeout check: which periodic IDs have exceeded their deadline at
    // now_us? Emits one synthetic RecordEntry per missing ID into 'out'
    // (that can_id, dlc=0, flags=MessageMissing, timestamp=now_us) and
    // will not re-emit until the ID is seen again.
    void check_timeouts(uint64_t now_us, std::vector<RecordEntry>& out);

private:
    struct State {
        MessageProfile profile;
        uint64_t last_seen_us = 0;
        bool     seen = false;
        bool     flagged_missing = false;
    };

    std::unordered_map<uint32_t, State> states_;
};

}  // namespace edr

#endif  // EDR_IDS_HPP
