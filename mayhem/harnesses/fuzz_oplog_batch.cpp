// Fuzz the HA oplog batch codec (mooncake-store ha/oplog/oplog_batch_codec).
// A standby master reads OpLogBatchRecord and DurablePrefix values that the
// primary wrote to the shared HA backend (etcd/redis) and decodes them with
// DecodeOpLogBatchRecord / DecodeDurablePrefix; whoever can write that
// backend controls these bytes. The first byte selects the decoder; a
// successfully decoded value is re-encoded and decoded again, which must
// succeed.
#include <string>

#include "fuzz_common.h"
#include "ha/oplog/oplog_batch_codec.h"

using namespace mooncake;

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    mayhem_fuzz::InitQuietLogging();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return -1;
    const std::string value(reinterpret_cast<const char *>(data) + 1, size - 1);
    std::string reason;
    if (data[0] & 1) {
        DurablePrefix prefix;
        if (DecodeDurablePrefix(value, &prefix, &reason)) {
            DurablePrefix again;
            if (!DecodeDurablePrefix(EncodeDurablePrefix(prefix), &again,
                                     &reason))
                abort();
        }
    } else {
        OpLogBatchRecord batch;
        if (DecodeOpLogBatchRecord(value, &batch, &reason)) {
            OpLogBatchRecord again;
            if (!DecodeOpLogBatchRecord(EncodeOpLogBatchRecord(batch), &again,
                                        &reason))
                abort();
        }
    }
    return 0;
}
