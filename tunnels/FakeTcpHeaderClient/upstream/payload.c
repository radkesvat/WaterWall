#include "structure.h"

#include "loggers/network_logger.h"

void faketcpheaderclientUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    assert(lineIsOnCurrentWorker(l));
    assert(tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l));
    faketcpheaderclient_tstate_t *state = tunnelGetState(t);

    const faketcpheader_wire_result_t result =
        faketcpheaderWireEncode(&state->wire,
                                faketcpheaderWireStateCount(&state->wire) != 0 ? state->values : NULL,
                                kFakeTcpHeaderWireClient,
                                buf);
    if (result != kFakeTcpHeaderWireOk)
    {
        if (atomicLogRateLimiterShouldLog(&state->drop_log_limiter, kFakeTcpHeaderClientDropLogIntervalMs))
        {
            LOGE("FakeTcpHeaderClient: dropping outgoing native packet: %s (packet-bytes=%u, max-native-bytes=%u, "
                 "overhead-bytes=%u, headroom-bytes=%u)",
                 faketcpheaderWireResultName(result),
                 (unsigned int) sbufGetLength(buf),
                 (unsigned int) faketcpheaderWireMaxNativeLength(&state->wire),
                 (unsigned int) faketcpheaderWireOverhead(&state->wire),
                 (unsigned int) sbufGetHeadroom(buf));
        }
        lineReuseBuffer(l, buf);
        return;
    }

    tunnelNextUpStreamPayload(t, l, buf);
}
