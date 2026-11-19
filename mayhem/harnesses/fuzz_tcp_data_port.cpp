// Fuzz the TCP transport's data port (server side of TcpTransport).
//
// A TransferEngine with the TCP transport installed accepts connections from
// any peer on its tcp_data_port and serves a stream of requests: a
// SessionHeader {u64 size, u64 addr, u8 opcode} (24 bytes in memory/on the
// wire, little-endian fields), then for WRITE the payload to store at addr,
// while READ streams addr..addr+size back. The opcode's high bit selects the
// acknowledged (v2) framing. addr is validated against the registered local
// buffers (validateTcpAddress) before the session touches memory.
//
// The engine and one registered 64 KiB buffer live for the whole process.
// The peer learns the buffer's address from the published segment descriptor;
// the harness models that by treating each header's addr as an offset from
// the buffer base (addr_on_wire = base + addr_in_input, wrapping), so inputs
// are independent of where the buffer was mapped. Nothing else in the stream
// is changed. Each input is one connection: the bytes are sent, the write
// side shut down, and the reply drained until the server closes. The buffer
// is reset before every input, so a WRITE in one input is not visible to the
// next.
#include <endian.h>
#include <sys/mman.h>

#include <vector>

#include "common.h"
#include "config.h"
#include "fuzz_common.h"
#include "transfer_engine.h"
#include "transport/transport.h"

using namespace mooncake;

namespace {
constexpr size_t kBufferSize = 64 * 1024;
constexpr size_t kHeaderSize = 24;  // sizeof(SessionHeader) incl. padding
TransferEngine *g_engine = nullptr;
char *g_buffer = nullptr;
uint16_t g_data_port = 0;
}  // namespace

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    // globalConfig() loads MC_* settings once and sets the glog level;
    // load it first so the quiet level below sticks.
    (void)globalConfig();
    mayhem_fuzz::InitQuietLogging();
    uint16_t rpc_port = 0;
    int probe = mayhem_fuzz::ListenLoopback(&rpc_port);
    if (probe < 0) abort();
    ::close(probe);
    const std::string name = "127.0.0.1:" + std::to_string(rpc_port);

    g_engine = new TransferEngine(false);
    if (g_engine->init(P2PHANDSHAKE, name, "127.0.0.1", rpc_port) != 0) abort();
    if (!g_engine->installTransport("tcp", nullptr)) abort();
    g_buffer = static_cast<char *>(::mmap(nullptr, kBufferSize,
                                          PROT_READ | PROT_WRITE,
                                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (g_buffer == MAP_FAILED) abort();
    if (g_engine->registerLocalMemory(g_buffer, kBufferSize, "cpu:0") != 0)
        abort();
    auto desc = g_engine->getMetadata()->getSegmentDescByID(LOCAL_SEGMENT_ID);
    if (!desc || desc->tcp_data_port <= 0) abort();
    g_data_port = static_cast<uint16_t>(desc->tcp_data_port);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    for (size_t i = 0; i < kBufferSize; ++i) g_buffer[i] = static_cast<char>(i);

    std::vector<uint8_t> wire(data, data + size);
    const uint64_t base = reinterpret_cast<uint64_t>(g_buffer);
    size_t off = 0;
    while (off + kHeaderSize <= wire.size()) {
        uint64_t req_size, addr;
        memcpy(&req_size, &wire[off], 8);
        memcpy(&addr, &wire[off + 8], 8);
        const uint8_t opcode = wire[off + 16];
        addr = htole64(le64toh(addr) + base);
        memcpy(&wire[off + 8], &addr, 8);
        off += kHeaderSize;
        if ((opcode & 0x7f) == TransferRequest::WRITE) {
            uint64_t body = le64toh(req_size);
            off += body < wire.size() - off ? body : wire.size() - off;
        }
    }

    int fd = mayhem_fuzz::ConnectLoopback(g_data_port);
    if (fd < 0) abort();
    mayhem_fuzz::WriteAll(fd, wire.data(), wire.size());
    ::shutdown(fd, SHUT_WR);
    mayhem_fuzz::DrainUntilEof(fd);
    ::close(fd);
    return 0;
}
