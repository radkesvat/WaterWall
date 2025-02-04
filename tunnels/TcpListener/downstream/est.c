#include "structure.h"

#include "loggers/network_logger.h"

void tcplistenerTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    tcplistener_lstate_t *lstate = lineGetState(l, t);

    assert(! lstate->established);
    lstate->established = true;
    wioSetKeepaliveTimeout(lstate->io, kEstablishedKeepAliveTimeOutMs);
}
