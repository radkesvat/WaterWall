#include "structure.h"

void domainresolverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    domainresolverLinestateDestroy(t, l, lineGetState(l, t));
    tunnelPrevDownStreamFinish(t, l);
}
