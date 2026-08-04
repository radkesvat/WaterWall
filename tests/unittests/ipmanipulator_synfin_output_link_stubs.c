#include "IpManipulator/structure.h"

void ipmanipulatorSynfinTestScheduleTimed(wid_t wid, WorkerMessageCallback callback,
                                          WorkerMessageCleanupCallback cleanup, uint32_t delay_ms, void *arg1,
                                          void *arg2, void *arg3);

ipmanipulator_tls_clienthello_start_status_e ipmanipulatorInspectTlsPayloadClientHelloStart(
    const uint8_t *payload, uint32_t payload_len, uint32_t *tls_record_total_len_out)
{
    discard payload;
    discard payload_len;
    *tls_record_total_len_out = 0;
    return kIpManipulatorTlsClientHelloStartMiss;
}

uint64_t ipmanipulatorAllocateFlowGeneration(ipmanipulator_tstate_t *state)
{
    discard state;
    return 1;
}

void ipmanipulatorForwardCapturedPacketNormal(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    lineReuseBuffer(l, buf);
}

void ipmanipulatorSynfinTestScheduleTimed(wid_t wid, WorkerMessageCallback callback,
                                          WorkerMessageCleanupCallback cleanup, uint32_t delay_ms, void *arg1,
                                          void *arg2, void *arg3)
{
    discard wid;
    discard callback;
    discard delay_ms;
    cleanup(arg1, arg2, arg3);
}
