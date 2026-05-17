#include "structure.h"

#include "loggers/network_logger.h"

void tlsserverTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    tlsserver_tstate_t *ts = tunnelGetState(t);
    if (ts->verbose)
    {
        LOGD("TlsServer: worker %u forwarding downstream Est", (unsigned int) lineGetWID(l));
    }
    tunnelPrevDownStreamEst(t, l);
}
