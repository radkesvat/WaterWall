#include "structure.h"

#include "loggers/network_logger.h"

void tcplistenerTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    tcplistener_lstate_t *ls = lineGetState(l, t);
    tcplistener_tstate_t *ts     = tunnelGetState(t);

    lineMarkEstablished(l);
    idleTableKeepIdleItemForAtleast(ts->idle_table, ls->idle_handle, kEstablishedKeepAliveTimeOutMs);
}
