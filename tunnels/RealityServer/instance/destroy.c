#include "structure.h"

void realityserverTunnelDestroy(tunnel_t *t)
{
    realityserver_tstate_t *ts = tunnelGetState(t);
    realityserverTunnelstateDestroy(ts);
    tunnelDestroy(t);
}
