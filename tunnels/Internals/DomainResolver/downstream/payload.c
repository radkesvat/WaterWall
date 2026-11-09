#include "structure.h"

void domainresolverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    domainresolver_lstate_t *ls = lineGetState(l, t);

    if (ls->dns_transport != NULL)
    {
        domainresolverTransportPayload(t, l, buf);
        return;
    }

    if (ls->phase != kDomainResolverPhaseOpen)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}
