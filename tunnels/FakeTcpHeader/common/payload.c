#include "structure.h"

#include "loggers/network_logger.h"

void faketcpheaderProcessPayload(tunnel_t *t, line_t *l, sbuf_t *buf, bool upstream)
{
    assert(lineIsOnCurrentWorker(l));
    assert(tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l));
    faketcpheader_tstate_t *state  = tunnelGetState(t);
    const bool              encode = upstream != state->server;
    if (! (encode ? faketcpheaderEncode(state, buf) : faketcpheaderDecode(state, buf)))
    {
        if (atomicLogRateLimiterShouldLog(&state->drop_log, 5000))
            LOGW("FakeTcpHeader: dropping invalid, oversized or unchecksummable %s packet",
                 encode ? "inner IPv4" : "carrier");
        lineReuseBuffer(l, buf);
        return;
    }
    if (upstream)
        tunnelNextUpStreamPayload(t, l, buf);
    else
        tunnelPrevDownStreamPayload(t, l, buf);
}
