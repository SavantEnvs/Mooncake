// Fuzz the peer segment descriptor a P2PHANDSHAKE client receives.
//
// A TransferMetadata client in P2PHANDSHAKE mode fetches a remote segment by
// connecting to the peer's handshake port and sending a Metadata request; the
// peer answers with a length-prefixed, typed frame whose payload is the
// segment descriptor JSON. That reply is fully peer-controlled. Here the
// harness plays the peer on 127.0.0.1: for each input it accepts the client's
// connection, reads its request, and answers with a Metadata frame carrying
// the fuzz bytes as payload. The client then runs the real code path:
// SocketHandShakePlugin::exchangeMetadata -> readString -> parseJsonString ->
// TransferMetadata::decodeSegmentDesc (incl. Topology::parse of the
// priority_matrix). A decoded descriptor is then used the way transports use
// it: buffers are looked up by address and devices selected via topology.
//
// State kept across inputs: one client TransferMetadata (its local segment is
// fixed and getSegmentDesc() does not cache the fetched descriptor) and the
// listening socket. Each input gets its own connection.
#include <poll.h>

#include <thread>

#include "common.h"
#include "config.h"
#include "fuzz_common.h"
#include "transfer_metadata.h"

using namespace mooncake;

namespace {
TransferMetadata *g_client = nullptr;
int g_listen_fd = -1;
std::string g_peer_name;

std::shared_ptr<TransferMetadata::SegmentDesc> MakeLocalDesc() {
    auto desc = std::make_shared<TransferMetadata::SegmentDesc>();
    desc->name = "127.0.0.1:0";
    desc->protocol = "rdma";
    TransferMetadata::DeviceDesc dev;
    dev.name = "mlx5_0";
    dev.lid = 1;
    dev.gid = "00000000000000000000ffff7f000001";
    desc->devices.push_back(dev);
    TransferMetadata::BufferDesc buf;
    buf.name = "cpu:0";
    buf.addr = 0x3000;
    buf.length = 4096;
    buf.lkey.push_back(1);
    buf.rkey.push_back(2);
    desc->buffers.push_back(buf);
    return desc;
}

// The fake peer: serve exactly one Metadata exchange with |payload|.
void ServeOnce(const uint8_t *data, size_t size) {
    pollfd pfd{g_listen_fd, POLLIN, 0};
    // The client connects right after this thread starts; if it never does
    // (it bailed out before connecting), there is nothing to serve.
    if (::poll(&pfd, 1, 2000) <= 0) return;
    int fd = ::accept(g_listen_fd, nullptr, nullptr);
    if (fd < 0) return;
    // Consume the client's request frame: u64 length + body.
    uint64_t len = 0;
    if (::recv(fd, &len, sizeof(len), MSG_WAITALL) == (ssize_t)sizeof(len) &&
        len > 0 && len <= (1u << 20)) {
        std::string body(len, '\0');
        ::recv(fd, body.data(), len, MSG_WAITALL);
    }
    // Reply: u64 length (type byte + payload), type, payload.
    uint64_t out_len = size + 1;
    uint8_t type = static_cast<uint8_t>(HandShakeRequestType::Metadata);
    mayhem_fuzz::WriteAll(fd, &out_len, sizeof(out_len));
    mayhem_fuzz::WriteAll(fd, &type, 1);
    mayhem_fuzz::WriteAll(fd, data, size);
    ::shutdown(fd, SHUT_WR);
    mayhem_fuzz::DrainUntilEof(fd);
    ::close(fd);
}

void UseDescriptor(TransferMetadata::SegmentDesc &desc) {
    // Consume the descriptor the way the RDMA transport's submit path does
    // (worker_pool.cpp selectPeerDevice): pick a device for each buffer from
    // the peer's priority matrix, bound it by that buffer's rkey vector, then
    // read the peer device entry it names.
    for (const auto &buf : desc.buffers) {
        for (int retry = 0; retry < 2; ++retry) {
            int device_id = desc.topology.selectDevice(buf.name, retry);
            if (device_id < 0 || (size_t)device_id >= buf.rkey.size()) continue;
            std::string peer_nic = desc.name + "@" + desc.devices[device_id].name;
            volatile uint32_t rkey = buf.rkey[device_id];
            (void)rkey;
            (void)peer_nic;
        }
    }
    (void)desc.topology.toString();
}
}  // namespace

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    // globalConfig() loads MC_* settings once and sets the glog level;
    // load it first so the quiet level below sticks.
    (void)globalConfig();
    mayhem_fuzz::InitQuietLogging();
    uint16_t port = 0;
    g_listen_fd = mayhem_fuzz::ListenLoopback(&port);
    if (g_listen_fd < 0) abort();
    g_peer_name = "127.0.0.1:" + std::to_string(port);
    g_client = new TransferMetadata(P2PHANDSHAKE);
    if (g_client->addLocalSegment(LOCAL_SEGMENT_ID, "127.0.0.1:0",
                                  MakeLocalDesc()) != 0)
        abort();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // readString() rejects frames above getHandshakeMaxLength() (1 MiB by
    // default) before parsing; larger inputs only exercise that check.
    if (size + 1 > getHandshakeMaxLength()) return -1;
    std::thread peer(ServeOnce, data, size);
    auto desc = g_client->getSegmentDesc(g_peer_name);
    peer.join();
    if (desc) UseDescriptor(*desc);
    return 0;
}
