// Fuzz the P2P handshake daemon (the transfer engine's RPC/handshake port).
//
// Every TransferMetadata in P2PHANDSHAKE mode listens on a TCP port and
// accepts frames from any peer: u64 native-endian length, then a payload
// whose first byte is a HandShakeRequestType (Connection/Metadata/Notify/
// Probe) or, for the old protocol, raw JSON. The daemon parses the JSON and
// dispatches to TransferHandshakeUtil::decode (Connection),
// receivePeerMetadata, receivePeerNotify and receivePeerProbe, then writes a
// reply. Here one daemon runs on 127.0.0.1 for the whole process; each input
// is written verbatim to a fresh connection, the write side is shut down
// (so a short frame ends at EOF instead of the 5 s receive timeout), and the
// harness reads until the daemon closes, so the input is fully processed
// before the next one.
//
// State kept across inputs: the daemon and its local segment. Notifies an
// input queues are drained after it, so the next input starts empty.
#include "common.h"
#include "config.h"
#include "fuzz_common.h"
#include "transfer_metadata.h"

using namespace mooncake;

namespace {
TransferMetadata *g_server = nullptr;
uint16_t g_port = 0;
}  // namespace

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    // globalConfig() loads MC_* settings once and sets the glog level;
    // load it first so the quiet level below sticks.
    (void)globalConfig();
    mayhem_fuzz::InitQuietLogging();
    int sockfd = mayhem_fuzz::ListenLoopback(&g_port);
    if (sockfd < 0) abort();
    const std::string name = "127.0.0.1:" + std::to_string(g_port);
    g_server = new TransferMetadata(P2PHANDSHAKE);

    auto desc = std::make_shared<TransferMetadata::SegmentDesc>();
    desc->name = name;
    desc->protocol = "tcp";
    desc->tcp_data_port = 0;
    TransferMetadata::BufferDesc buf;
    buf.name = "cpu:0";
    buf.addr = 0x10000;
    buf.length = 4096;
    desc->buffers.push_back(buf);
    if (g_server->addLocalSegment(LOCAL_SEGMENT_ID, name, std::move(desc)))
        abort();

    TransferMetadata::RpcMetaDesc rpc;
    rpc.ip_or_host_name = "127.0.0.1";
    rpc.rpc_port = g_port;
    rpc.sockfd = sockfd;
    if (g_server->addRpcMetaEntry(name, rpc)) abort();
    // Connection requests are decoded into a HandShakeDesc and handed to the
    // transport's callback; accept them like a transport would.
    if (g_server->startHandshakeDaemon(
            [](const TransferMetadata::HandShakeDesc &,
               TransferMetadata::HandShakeDesc &) { return 0; },
            g_port, sockfd))
        abort();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    int fd = mayhem_fuzz::ConnectLoopback(g_port);
    if (fd < 0) abort();
    mayhem_fuzz::WriteAll(fd, data, size);
    ::shutdown(fd, SHUT_WR);
    mayhem_fuzz::DrainUntilEof(fd);
    ::close(fd);
    std::vector<TransferMetadata::NotifyDesc> notifies;
    g_server->getNotifies(notifies);
    return 0;
}
