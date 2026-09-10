#ifndef EDR_SOCKET_CAN_SOURCE_HPP
#define EDR_SOCKET_CAN_SOURCE_HPP

#include <cstdint>
#include <string>

#include "edr/can_source.hpp"

namespace edr {

// Linux SocketCAN implementation of ICanSource. Reads real frames from a
// can/vcan interface. Construction never throws: on failure fd_ stays -1
// and is_open() reports it.
class SocketCanSource : public ICanSource {
public:
    // read_timeout_ms bounds how long read() blocks so the caller can
    // keep polling the IDS even when the bus goes silent.
    explicit SocketCanSource(const std::string& ifname,
                             uint32_t read_timeout_ms = 100);
    ~SocketCanSource() override;

    SocketCanSource(const SocketCanSource&) = delete;
    SocketCanSource& operator=(const SocketCanSource&) = delete;

    SocketCanSource(SocketCanSource&& other) noexcept;
    SocketCanSource& operator=(SocketCanSource&& other) noexcept;

    bool read(RecordEntry& out) override;

    bool is_open() const { return fd_ >= 0; }

private:
    void close_fd();

    int fd_ = -1;  // raw CAN socket descriptor
};

}  // namespace edr

#endif  // EDR_SOCKET_CAN_SOURCE_HPP
