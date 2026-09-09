#include "edr/socket_can_source.hpp"

#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <ctime>
#include <utility>

namespace edr {

SocketCanSource::SocketCanSource(const std::string& ifname) {
    // 1. Open a raw CAN socket.
    fd_ = ::socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (fd_ < 0) {
        fd_ = -1;
        return;
    }

    // 2. Ask the kernel to timestamp every received frame.
    const int on = 1;
    if (::setsockopt(fd_, SOL_SOCKET, SO_TIMESTAMP, &on, sizeof(on)) < 0) {
        close_fd();
        return;
    }

    // 3. Resolve the interface name to its index.
    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
    if (::ioctl(fd_, SIOCGIFINDEX, &ifr) < 0) {
        close_fd();
        return;
    }

    // 4. Bind the socket to that interface.
    struct sockaddr_can addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    if (::bind(fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        close_fd();
        return;
    }
}

SocketCanSource::~SocketCanSource() {
    close_fd();
}

SocketCanSource::SocketCanSource(SocketCanSource&& other) noexcept
    : fd_(other.fd_) {
    other.fd_ = -1;
}

SocketCanSource& SocketCanSource::operator=(SocketCanSource&& other) noexcept {
    if (this != &other) {
        close_fd();
        fd_ = other.fd_;
        other.fd_ = -1;
    }
    return *this;
}

void SocketCanSource::close_fd() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

bool SocketCanSource::read(RecordEntry& out) {
    if (!is_open()) {
        return false;
    }

    struct can_frame frame;
    std::memset(&frame, 0, sizeof(frame));

    struct iovec iov;
    iov.iov_base = &frame;
    iov.iov_len = sizeof(frame);

    // Ancillary buffer large enough for one SCM_TIMESTAMP timeval.
    char control[CMSG_SPACE(sizeof(struct timeval))];

    struct msghdr msg;
    std::memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    const ssize_t n = ::recvmsg(fd_, &msg, 0);
    if (n < static_cast<ssize_t>(sizeof(struct can_frame))) {
        return false;
    }

    // Pull the kernel timestamp out of the control messages.
    struct timeval tv;
    std::memset(&tv, 0, sizeof(tv));
    bool have_ts = false;
    for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr;
         cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMP &&
            cmsg->cmsg_len >= CMSG_LEN(sizeof(struct timeval))) {
            std::memcpy(&tv, CMSG_DATA(cmsg), sizeof(tv));
            have_ts = true;
            break;
        }
    }

    if (have_ts) {
        out.timestamp_us = static_cast<uint64_t>(tv.tv_sec) * 1000000ULL +
                           static_cast<uint64_t>(tv.tv_usec);
    } else {
        out.timestamp_us = 0;
    }

    out.can_id = frame.can_id;  // raw id, flag bits included

    uint8_t dlc = frame.can_dlc;
    if (dlc > 8) {
        dlc = 8;
    }
    out.dlc = dlc;

    std::memcpy(out.data, frame.data, dlc);
    if (dlc < 8) {
        std::memset(out.data + dlc, 0, 8 - dlc);
    }

    out.flags = 0;  // anomaly marking is the IDS's job

    return true;
}

}  // namespace edr
