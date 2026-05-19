#include "structure.h"

#include "loggers/network_logger.h"

void testerserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    testerserver_tstate_t *ts = tunnelGetState(t);
    testerserver_lstate_t *ls = lineGetState(l, t);

    if (! ts->packet_mode)
    {
        discard buf;
        LOGF("TesterServer: downStreamPayload disabled");
        assert(false);
        return;
    }

    ls->response_to_next = true;
    testerserverHandlePacketRequestPayload(t, l, buf);
}
