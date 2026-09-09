#ifndef EDR_RING_BUFFER_HPP
#define EDR_RING_BUFFER_HPP

#include <cstddef>
#include <cstdint>

#include "edr/record.hpp"

namespace edr {

// Fixed-size circular buffer with overwrite semantics: once full, push
// drops the oldest entry instead of failing. Keeps the last N records.
// All storage is static; no heap, no dynamic size.
template <typename T, std::size_t N>
class RingBuffer {
    static_assert(N > 0, "RingBuffer capacity must be greater than zero");

public:
    // Append an item. Never fails: when full, the oldest entry is evicted.
    void push(const T& item) {
        data_[head_] = item;

        ++head_;
        if (head_ == N) {
            head_ = 0;
        }

        if (count_ == N) {
            ++tail_;
            if (tail_ == N) {
                tail_ = 0;
            }
        } else {
            ++count_;
        }
    }

    std::size_t size() const { return count_; }
    std::size_t capacity() const { return N; }
    bool empty() const { return count_ == 0; }
    bool full() const { return count_ == N; }

    void clear() {
        head_ = 0;
        tail_ = 0;
        count_ = 0;
    }

    // Snapshot read: visit every entry from oldest to newest without
    // consuming. Used to dump the buffer to disk.
    template <typename Fn>
    void for_each(Fn fn) const {
        std::size_t idx = tail_;
        for (std::size_t i = 0; i < count_; ++i) {
            fn(data_[idx]);
            ++idx;
            if (idx == N) {
                idx = 0;
            }
        }
    }

private:
    T data_[N];
    std::size_t head_ = 0;   // next write position
    std::size_t tail_ = 0;   // position of the oldest entry
    std::size_t count_ = 0;  // number of entries held
};

}  // namespace edr

#endif  // EDR_RING_BUFFER_HPP
