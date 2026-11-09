#include "structure.h"

void domainresolverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    domainresolver_lstate_t *ls = lineGetState(l, t);
    if (ls->dns_transport != NULL)
    {
        domainresolverTransportFinish(t, l);
        return;
    }
    domainresolverLinestateDestroy(t, l, lineGetState(l, t));
    tunnelPrevDownStreamFinish(t, l);
}
