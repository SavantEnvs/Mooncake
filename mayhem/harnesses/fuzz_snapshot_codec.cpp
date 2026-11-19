// Fuzz the HA batch-oplog snapshot decoders (mooncake-store
// ha/snapshot/batch_oplog/{codec,metadata}). A standby or a restarting
// master loads snapshot objects (segments, weight metadata, object chunks)
// and the snapshot descriptor/manifest from the snapshot store (object
// storage or local FS), so their bytes come from outside the process. The
// first byte selects one of the five public Decode* entry points; the rest
// is the encoded object.
#include <string_view>
#include <vector>

#include "fuzz_common.h"
#include "ha/snapshot/batch_oplog/codec.h"
#include "ha/snapshot/batch_oplog/metadata.h"

using namespace mooncake;

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    mayhem_fuzz::InitQuietLogging();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return -1;
    const uint8_t selector = data[0];
    const uint8_t *body = data + 1;
    const size_t body_size = size - 1;
    std::vector<uint8_t> bytes(body, body + body_size);
    std::string_view text(reinterpret_cast<const char *>(body), body_size);
    switch (selector % 5) {
        case 0: {
            auto r = DecodeBatchOpLogSnapshotSegments(bytes);
            if (r) (void)EncodeBatchOpLogSnapshotSegments(*r);
            break;
        }
        case 1: {
            auto r = DecodeBatchOpLogSnapshotWeightMetadata(bytes);
            if (r) (void)EncodeBatchOpLogSnapshotWeightMetadata(*r);
            break;
        }
        case 2: {
            // The loader passes the chunk index and object count recorded in
            // the manifest; take them from the selector byte's high bits.
            auto r = DecodeBatchOpLogSnapshotObjectChunk(bytes, selector >> 5,
                                                         (selector >> 3) & 3);
            (void)r;
            break;
        }
        case 3: {
            auto r = ha::DecodeBatchOpLogSnapshotDescriptor(text);
            if (r) (void)ha::EncodeBatchOpLogSnapshotDescriptor(*r);
            break;
        }
        case 4: {
            auto r = ha::DecodeBatchOpLogSnapshotManifest(text);
            if (r) (void)ha::EncodeBatchOpLogSnapshotManifest(*r);
            break;
        }
    }
    return 0;
}
