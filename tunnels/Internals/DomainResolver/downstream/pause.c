#include "structure.h"

void domainresolverTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    domainresolver_lstate_t *ls = lineGetState(l, t);
    ls->next_paused             = true;
    discard domainresolverUpdateSourcePressure(t, l);
}
