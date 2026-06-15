#include "structure.h"

void tcpudpconnectorTunnelOnStop(tunnel_t *t)
{
    discard t;
}

void tcpudpconnectorTunnelOnWorkerStop(tunnel_t *t, wid_t wid)
{
    discard t;
    discard wid;
}
