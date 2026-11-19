// Fuzz Topology::parse, the decoder for the transfer engine's topology /
// priority-matrix JSON ({"<storage>": [[preferred HCAs], [available HCAs]]}).
// The same JSON arrives from peers as the "priority_matrix" field of every
// RDMA segment descriptor and from MC_CUSTOM_TOPO_JSON. A parsed topology is
// then queried as the transports do (selectDevice / getDeviceIndex over each
// storage type, toString/toJson round trip).
#include "config.h"
#include "fuzz_common.h"
#include "topology.h"

using namespace mooncake;

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    // globalConfig() loads MC_* settings once and sets the glog level;
    // load it first so the quiet level below sticks.
    (void)globalConfig();
    mayhem_fuzz::InitQuietLogging();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Topology topo;
    if (topo.parse(std::string(reinterpret_cast<const char *>(data), size)) != 0)
        return 0;
    Json::Value json = topo.toJson();
    for (const auto &storage : json.getMemberNames()) {
        for (int retry = 0; retry < 3; ++retry) {
            int dev = topo.selectDevice(storage, retry);
            (void)dev;
        }
    }
    (void)topo.selectDevice("cpu:0", 0);
    Topology again;
    (void)again.parse(topo.toString());
    return 0;
}
