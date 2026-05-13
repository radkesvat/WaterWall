#include "structure.h"

#include "loggers/network_logger.h"

void testerserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    testerserver_tstate_t *ts = tunnelGetState(t);
    testerserver_lstate_t *ls = lineGetState(l, t);

    if (ts->packet_mode)
    {
        testerserverFail(t, l, "packet-mode received unexpected finish on worker packet line");
        return;
    }

    if (ls->request_rx_index != testerserverGetChunkCount(t) || ! ls->response_ready)
    {
        testerserverFail(t, l, "received finish before full request verification");
        return;
    }

    if (! ls->response_sent)
    {
        testerserverFail(t, l, "received finish before sending the full response sequence");
        return;
    }

    testerserverLinestateDestroy(ls);
}
