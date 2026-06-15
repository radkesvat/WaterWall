#include "structure.h"

void tcpudplistenerTunnelOnStop(tunnel_t *t)
{
    discard t;
}

void tcpudplistenerTunnelOnWorkerStop(tunnel_t *t, wid_t wid)
{
    discard t;
    discard wid;
}
