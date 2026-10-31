#include "structure.h"

#include "loggers/network_logger.h"

void faketcpheaderserverDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    assert(lineIsOnCurrentWorker(l));
    assert(tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l));
    faketcpheaderserver_tstate_t *state = tunnelGetState(t);

    const faketcpheader_wire_result_t result = faketcpheaderWireEncode(&state->wire, kFakeTcpHeaderWireServer, buf);
    if (result != kFakeTcpHeaderWireOk)
    {
        if (atomicLogRateLimiterShouldLog(&state->drop_log_limiter, kFakeTcpHeaderServerDropLogIntervalMs))
        {
            LOGE("FakeTcpHeaderServer: dropping outgoing inner packet: %s (packet-bytes=%u, max-inner-bytes=%u, "
                 "overhead-bytes=%u, headroom-bytes=%u)",
                 faketcpheaderWireResultName(result),
                 (unsigned int) sbufGetLength(buf),
                 (unsigned int) faketcpheaderWireMaxInnerLength(&state->wire),
                 (unsigned int) faketcpheaderWireOverhead(&state->wire),
                 (unsigned int) sbufGetLeftCapacity(buf));
        }
        lineReuseBuffer(l, buf);
        return;
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}
