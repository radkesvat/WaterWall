#include "structure.h"

void domainresolverTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    domainresolver_lstate_t *ls = lineGetState(l, t);
    ls->prev_paused             = false;
    if (ls->phase != kDomainResolverPhaseOpen || ! ls->read_pause_sent)
        return;
    ls->read_pause_sent = false;
    tunnelNextUpStreamResume(t, l);
}
