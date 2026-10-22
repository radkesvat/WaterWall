#include "structure.h"

void quicserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    quicDestroyState(t);
    tunnelDestroy(t);
}
