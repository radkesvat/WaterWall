#include "structure.h"

#include "loggers/network_logger.h"

void connectionfisherserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    connectionfisherserver_lstate_t *ls = lineGetState(l, t);

    if (ls->phase != kConnectionFisherServerPhaseEstablished)
    {
        LOGW("ConnectionFisherServer: unexpected downstream payload before the probe handshake completed");
        lineReuseBuffer(l, buf);
        connectionfisherserverCloseLineFromDownstream(t, l);
        return;
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}
