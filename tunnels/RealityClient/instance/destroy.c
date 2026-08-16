#include "structure.h"

void realityclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                 context;
    realityclient_tstate_t *ts = tunnelGetState(t);
    realityclientTunnelstateDestroy(ts);
    tunnelDestroy(t);
}
