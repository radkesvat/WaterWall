#include "structure.h"

#include "loggers/network_logger.h"

void faketcpheaderclientDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    assert(lineIsOnCurrentWorker(l));
    assert(tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l));
    faketcpheaderclient_tstate_t *state = tunnelGetState(t);

    const faketcpheader_wire_result_t result = faketcpheaderWireDecode(&state->wire, kFakeTcpHeaderWireClient, buf);
    if (result != kFakeTcpHeaderWireOk)
    {
        if (atomicLogRateLimiterShouldLog(&state->drop_log_limiter, kFakeTcpHeaderClientDropLogIntervalMs))
        {
            LOGE("FakeTcpHeaderClient: dropping incoming carrier: %s (packet-bytes=%zu, max-carrier-bytes=%u)",
                 faketcpheaderWireResultName(result),
                 sbufGetLength(buf),
                 (unsigned int) kFakeTcpHeaderWireMaxCarrierLength);
        }
        lineReuseBuffer(l, buf);
        return;
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}
