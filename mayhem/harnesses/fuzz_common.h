// Shared helpers for the Mooncake fuzz harnesses (mayhem/ layer only).
#pragma once
#include <arpa/inet.h>
#include <glog/logging.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <string>

namespace mayhem_fuzz {

// Quiet glog once per process. Inputs cannot change this setting.
inline void InitQuietLogging() {
    static bool done = false;
    if (done) return;
    done = true;
    FLAGS_logtostderr = true;
    FLAGS_minloglevel = 3;  // FATAL only: LOG(FATAL)/CHECK still abort.
    if (!google::IsGoogleLoggingInitialized())
        google::InitGoogleLogging("mooncake-fuzz");
}

inline bool WriteAll(int fd, const void *buf, size_t len) {
    const char *p = static_cast<const char *>(buf);
    while (len > 0) {
        ssize_t n = ::send(fd, p, len, MSG_NOSIGNAL);
        if (n <= 0) return false;
        p += n;
        len -= static_cast<size_t>(n);
    }
    return true;
}

// Read until the peer closes; the bytes are discarded.
inline void DrainUntilEof(int fd) {
    char buf[4096];
    while (::recv(fd, buf, sizeof(buf), 0) > 0) {
    }
}

inline int ConnectLoopback(uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

// Bind + listen on an ephemeral 127.0.0.1 port; returns the fd, sets *port.
inline int ListenLoopback(uint16_t *port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t len = sizeof(addr);
    if (::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0 ||
        ::listen(fd, 64) != 0 ||
        ::getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len) != 0) {
        ::close(fd);
        return -1;
    }
    *port = ntohs(addr.sin_port);
    return fd;
}

}  // namespace mayhem_fuzz
