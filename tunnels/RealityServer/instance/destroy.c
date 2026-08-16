#include "structure.h"

void realityserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                 context;
    realityserver_tstate_t *ts = tunnelGetState(t);
    realityserverTunnelstateDestroy(ts);
    tunnelDestroy(t);
}
