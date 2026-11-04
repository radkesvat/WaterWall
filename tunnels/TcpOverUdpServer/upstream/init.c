#include "structure.h"

void tcpoverudpserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    /* The incoming normal line belongs to the UDP source. Service admission waits for CONFIRM. */
    tcpoverudpserver_lstate_t *ls = lineGetState(l, t);
    if (! tcpoverudpserverLinestateInitialize(ls, l, t))
    {
        tunnelPrevDownStreamFinish(t, l);
    }
}
