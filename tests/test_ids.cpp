#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <vector>

#include "edr/ids.hpp"
#include "edr/record.hpp"

using edr::AnomalyFlag;
using edr::Ids;
using edr::MessageProfile;
using edr::RecordEntry;

namespace {

constexpr uint8_t U(AnomalyFlag f) { return static_cast<uint8_t>(f); }

RecordEntry frame(uint32_t id, uint8_t dlc, uint64_t ts) {
    RecordEntry e{};
    e.can_id = id;
    e.dlc = dlc;
    e.timestamp_us = ts;
    return e;
}

Ids make_ids() {
    return Ids({
        {0x180, 8, 10000, 2000},  // periodic
        {0x200, 2, 0, 0},         // aperiodic
    });
}

}  // namespace

TEST_CASE("unknown id is flagged", "[ids]") {
    Ids ids = make_ids();
    REQUIRE(ids.inspect(frame(0x321, 8, 1000)) == U(AnomalyFlag::UnknownId));
}

TEST_CASE("first sighting is clean", "[ids]") {
    Ids ids = make_ids();
    REQUIRE(ids.inspect(frame(0x180, 8, 100000)) == 0);
}

TEST_CASE("on-time period is clean", "[ids]") {
    Ids ids = make_ids();
    ids.inspect(frame(0x180, 8, 100000));
    REQUIRE(ids.inspect(frame(0x180, 8, 110000)) == 0);
}

TEST_CASE("too-early arrival flags period violation", "[ids]") {
    Ids ids = make_ids();
    ids.inspect(frame(0x180, 8, 100000));
    // delta 3000 < 10000 - 2000 = 8000 -> injection.
    REQUIRE(ids.inspect(frame(0x180, 8, 103000)) ==
            U(AnomalyFlag::PeriodViolation));
}

TEST_CASE("wrong dlc is flagged", "[ids]") {
    Ids ids = make_ids();
    REQUIRE(ids.inspect(frame(0x180, 4, 100000)) == U(AnomalyFlag::InvalidDlc));
}

TEST_CASE("early and wrong dlc set both flags", "[ids]") {
    Ids ids = make_ids();
    ids.inspect(frame(0x180, 8, 100000));
    const uint8_t got = ids.inspect(frame(0x180, 3, 102000));
    REQUIRE(got == (U(AnomalyFlag::PeriodViolation) | U(AnomalyFlag::InvalidDlc)));
}

TEST_CASE("aperiodic id has no period check", "[ids]") {
    Ids ids = make_ids();
    REQUIRE(ids.inspect(frame(0x200, 2, 1000)) == 0);
    REQUIRE(ids.inspect(frame(0x200, 2, 1001)) == 0);  // back-to-back is fine
}

TEST_CASE("check_timeouts emits a synthetic missing record", "[ids]") {
    Ids ids = make_ids();
    ids.inspect(frame(0x180, 8, 100000));

    std::vector<RecordEntry> out;
    ids.check_timeouts(100000 + 10000 + 2000 + 1, out);

    REQUIRE(out.size() == 1);
    REQUIRE(out[0].can_id == 0x180);
    REQUIRE(out[0].dlc == 0);
    REQUIRE(out[0].flags == U(AnomalyFlag::MessageMissing));
    REQUIRE(out[0].timestamp_us == 100000 + 10000 + 2000 + 1);
}

TEST_CASE("the same miss is not re-emitted", "[ids]") {
    Ids ids = make_ids();
    ids.inspect(frame(0x180, 8, 100000));

    std::vector<RecordEntry> out;
    ids.check_timeouts(200000, out);
    REQUIRE(out.size() == 1);

    out.clear();
    ids.check_timeouts(300000, out);
    REQUIRE(out.empty());
}

TEST_CASE("recovery then a new miss emits again", "[ids]") {
    Ids ids = make_ids();
    ids.inspect(frame(0x180, 8, 100000));

    std::vector<RecordEntry> out;
    ids.check_timeouts(200000, out);
    REQUIRE(out.size() == 1);

    // Message comes back.
    REQUIRE(ids.inspect(frame(0x180, 8, 250000)) == 0);

    out.clear();
    ids.check_timeouts(300000, out);
    REQUIRE(out.size() == 1);
    REQUIRE(out[0].can_id == 0x180);
}

TEST_CASE("never-seen and aperiodic ids are not counted missing", "[ids]") {
    Ids ids = make_ids();
    // 0x180 never seen; 0x200 aperiodic and seen.
    ids.inspect(frame(0x200, 2, 1000));

    std::vector<RecordEntry> out;
    ids.check_timeouts(9999999, out);
    REQUIRE(out.empty());
}
