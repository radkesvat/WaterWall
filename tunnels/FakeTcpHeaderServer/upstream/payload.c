#include "structure.h"

#include "loggers/network_logger.h"

void faketcpheaderserverUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    assert(lineIsOnCurrentWorker(l));
    assert(tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l));
    faketcpheaderserver_tstate_t *state = tunnelGetState(t);

    const faketcpheader_wire_result_t result = faketcpheaderWireDecode(&state->wire, kFakeTcpHeaderWireServer, buf);
    if (result != kFakeTcpHeaderWireOk)
    {
        if (atomicLogRateLimiterShouldLog(&state->drop_log_limiter, kFakeTcpHeaderServerDropLogIntervalMs))
        {
            LOGE("FakeTcpHeaderServer: dropping incoming carrier: %s (packet-bytes=%u, max-carrier-bytes=%u)",
                 faketcpheaderWireResultName(result),
                 (unsigned int) sbufGetLength(buf),
                 (unsigned int) kFakeTcpHeaderWireMaxCarrierLength);
        }
        lineReuseBuffer(l, buf);
        return;
    }

    tunnelNextUpStreamPayload(t, l, buf);
}
