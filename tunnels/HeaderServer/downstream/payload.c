#include "structure.h"

#include "loggers/network_logger.h"

void headerserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    headerserver_lstate_t *ls = lineGetState(l, t);

    if (ls->phase != kHeaderServerPhaseEstablished)
    {
        LOGW("HeaderServer: unexpected downstream payload before header routing completed");
        lineReuseBuffer(l, buf);
        headerserverCloseLineFromDownstream(t, l);
        return;
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}
