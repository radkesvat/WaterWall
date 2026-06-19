#include "structure.h"

#include "loggers/network_logger.h"

void tlsserverTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    tlsserver_tstate_t *ts = tunnelGetState(t);
    tlsserver_lstate_t *ls = lineGetState(l, t);

    if (ls->prev_est_sent || lineIsEstablished(l))
    {
        return;
    }

    if (ts->verbose)
    {
        LOGD("TlsServer: worker %u forwarding downstream Est", (unsigned int) lineGetWID(l));
    }

    ls->prev_est_sent = true;
    tunnelPrevDownStreamEst(t, l);
}
