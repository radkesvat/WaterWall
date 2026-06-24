#include "structure.h"

void domainresolverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    domainresolverCloseLine(t, l, kDomainResolverDirectionDownstream);
}
