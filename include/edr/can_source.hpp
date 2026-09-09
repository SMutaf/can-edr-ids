#ifndef EDR_CAN_SOURCE_HPP
#define EDR_CAN_SOURCE_HPP

#include <cstddef>
#include <cstdint>
#include <vector>

#include "edr/record.hpp"

namespace edr {

// Abstract CAN frame source. Real socket-backed implementations live in
// their own translation units; this header stays platform independent.
class ICanSource {
public:
    virtual ~ICanSource() = default;

    // Read one frame. Returns true and fills 'out' on success,
    // false when the source is exhausted or errors.
    virtual bool read(RecordEntry& out) = 0;
};

// In-memory source backed by a preloaded frame list. Used to exercise
// the IDS and recorder without hardware.
class MockCanSource : public ICanSource {
public:
    explicit MockCanSource(std::vector<RecordEntry> frames)
        : frames_(std::move(frames)) {}

    bool read(RecordEntry& out) override {
        if (index_ >= frames_.size()) {
            return false;
        }
        out = frames_[index_];
        ++index_;
        return true;
    }

    bool empty() const { return index_ >= frames_.size(); }
    std::size_t remaining() const { return frames_.size() - index_; }

private:
    std::vector<RecordEntry> frames_;
    std::size_t index_ = 0;
};

}  // namespace edr

#endif  // EDR_CAN_SOURCE_HPP
