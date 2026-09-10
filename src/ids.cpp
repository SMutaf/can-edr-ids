#include "edr/ids.hpp"

#include <cstring>

namespace edr {

Ids::Ids(std::vector<MessageProfile> profiles) {
    for (const auto& p : profiles) {
        State s;
        s.profile = p;
        states_[p.can_id] = s;
    }
}

uint8_t Ids::inspect(const RecordEntry& entry) {
    uint8_t flags = 0;

    auto it = states_.find(entry.can_id);
    if (it == states_.end()) {
        // Unknown ID: no profile, so no DLC / period check.
        return static_cast<uint8_t>(AnomalyFlag::UnknownId);
    }

    State& st = it->second;
    const MessageProfile& prof = st.profile;

    // Rule 2: wrong payload length.
    if (entry.dlc != prof.expected_dlc) {
        flags |= static_cast<uint8_t>(AnomalyFlag::InvalidDlc);
    }

    // Rule 3: too-early arrival (injection). Late arrival is handled by
    // check_timeouts, not here.
    if (prof.period_us > 0 && st.seen) {
        const uint64_t delta = entry.timestamp_us - st.last_seen_us;
        const uint64_t min_gap =
            (prof.period_us > prof.tolerance_us)
                ? static_cast<uint64_t>(prof.period_us) - prof.tolerance_us
                : 0;
        if (delta < min_gap) {
            flags |= static_cast<uint8_t>(AnomalyFlag::PeriodViolation);
        }
    }

    // Message is present: refresh state and clear any missing mark.
    st.last_seen_us = entry.timestamp_us;
    st.seen = true;
    st.flagged_missing = false;

    return flags;
}

void Ids::check_timeouts(uint64_t now_us, std::vector<RecordEntry>& out) {
    for (auto& kv : states_) {
        State& st = kv.second;
        const MessageProfile& prof = st.profile;

        if (prof.period_us == 0 || !st.seen || st.flagged_missing) {
            continue;
        }

        const uint64_t deadline =
            st.last_seen_us + prof.period_us + prof.tolerance_us;
        if (now_us > deadline) {
            RecordEntry miss;
            std::memset(&miss, 0, sizeof(miss));
            miss.timestamp_us = now_us;
            miss.can_id = prof.can_id;
            miss.dlc = 0;
            miss.flags = static_cast<uint8_t>(AnomalyFlag::MessageMissing);
            out.push_back(miss);

            st.flagged_missing = true;
        }
    }
}

}  // namespace edr
