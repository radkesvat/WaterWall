#include "structure.h"

void softiplimiterTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(t != NULL);

    softiplimiterTunnelstateDestroy(tunnelGetState(t));
    tunnelDestroy(t);
}
