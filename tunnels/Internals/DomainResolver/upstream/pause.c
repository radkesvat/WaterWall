#include "structure.h"

void domainresolverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    domainresolver_lstate_t *ls = lineGetState(l, t);
    ls->prev_paused             = true;
    if (ls->phase != kDomainResolverPhaseOpen || ls->read_pause_sent)
        return;
    ls->read_pause_sent = true;
    tunnelNextUpStreamPause(t, l);
}
