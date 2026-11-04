#include "structure.h"

void domainresolverTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    domainresolver_lstate_t *ls = lineGetState(l, t);
    if (ls->chain_query != NULL)
    {
        dnslineclientOnLinePause(ls->chain_query, l);
        return;
    }
    ls->next_paused = true;
    discard domainresolverUpdateSourcePressure(t, l);
}
