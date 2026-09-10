#include <catch2/catch_test_macros.hpp>

#include <vector>

#include "edr/record.hpp"
#include "edr/ring_buffer.hpp"

using edr::RingBuffer;

namespace {
template <typename RB>
std::vector<int> dump(const RB& rb) {
    std::vector<int> out;
    rb.for_each([&](int v) { out.push_back(v); });
    return out;
}
}  // namespace

TEST_CASE("ring buffer starts empty", "[ring_buffer]") {
    RingBuffer<int, 4> rb;
    REQUIRE(rb.size() == 0);
    REQUIRE(rb.empty());
    REQUIRE_FALSE(rb.full());
    REQUIRE(rb.capacity() == 4);
}

TEST_CASE("push grows size until full", "[ring_buffer]") {
    RingBuffer<int, 4> rb;
    rb.push(1);
    REQUIRE(rb.size() == 1);
    rb.push(2);
    rb.push(3);
    REQUIRE(rb.size() == 3);
    REQUIRE_FALSE(rb.full());
    rb.push(4);
    REQUIRE(rb.size() == 4);
    REQUIRE(rb.full());
}

TEST_CASE("for_each walks oldest to newest before wrap", "[ring_buffer]") {
    RingBuffer<int, 4> rb;
    rb.push(10);
    rb.push(20);
    rb.push(30);
    REQUIRE(dump(rb) == std::vector<int>{10, 20, 30});
}

TEST_CASE("overwrite drops the oldest entry", "[ring_buffer]") {
    RingBuffer<int, 4> rb;
    for (int v : {1, 2, 3, 4, 5}) {
        rb.push(v);
    }
    REQUIRE(rb.size() == 4);
    REQUIRE(dump(rb) == std::vector<int>{2, 3, 4, 5});
}

TEST_CASE("wrap stress keeps the last N", "[ring_buffer]") {
    RingBuffer<int, 8> rb;
    for (int v = 0; v < 1000; ++v) {
        rb.push(v);
    }
    REQUIRE(rb.size() == 8);
    REQUIRE(dump(rb) == std::vector<int>{992, 993, 994, 995, 996, 997, 998, 999});
}

TEST_CASE("capacity one keeps only the latest", "[ring_buffer]") {
    RingBuffer<int, 1> rb;
    rb.push(7);
    REQUIRE(dump(rb) == std::vector<int>{7});
    rb.push(8);
    rb.push(9);
    REQUIRE(rb.size() == 1);
    REQUIRE(dump(rb) == std::vector<int>{9});
}

TEST_CASE("clear empties the buffer", "[ring_buffer]") {
    RingBuffer<int, 4> rb;
    rb.push(1);
    rb.push(2);
    rb.clear();
    REQUIRE(rb.empty());
    REQUIRE(rb.size() == 0);
    REQUIRE(dump(rb).empty());
    rb.push(42);
    REQUIRE(dump(rb) == std::vector<int>{42});
}

TEST_CASE("works with RecordEntry payloads", "[ring_buffer]") {
    RingBuffer<edr::RecordEntry, 2> rb;
    edr::RecordEntry a{};
    a.can_id = 0x111;
    edr::RecordEntry b{};
    b.can_id = 0x222;
    edr::RecordEntry c{};
    c.can_id = 0x333;
    rb.push(a);
    rb.push(b);
    rb.push(c);

    std::vector<uint32_t> ids;
    rb.for_each([&](const edr::RecordEntry& e) { ids.push_back(e.can_id); });
    REQUIRE(ids == std::vector<uint32_t>{0x222, 0x333});
}
