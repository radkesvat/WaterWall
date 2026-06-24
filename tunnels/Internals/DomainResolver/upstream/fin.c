#include "structure.h"

void domainresolverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    domainresolverCloseLine(t, l, kDomainResolverDirectionUpstream);
}
