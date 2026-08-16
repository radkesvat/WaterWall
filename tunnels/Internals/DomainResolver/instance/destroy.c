#include "structure.h"

void domainresolverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    tunnelDestroy(t);
}
