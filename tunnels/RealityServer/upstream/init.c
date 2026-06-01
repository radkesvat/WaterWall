#include "structure.h"

void realityserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    realityserver_tstate_t *ts = tunnelGetState(t);
    realityserver_lstate_t *ls = lineGetState(l, t);

    realityserverLinestateInitialize(ls, lineGetBufferPool(l));
    ls->destination_init_sent = true;

    withLineLocked(l, tunnelUpStreamInit, ts->destination_tunnel);
}
