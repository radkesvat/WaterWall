#include "structure.h"

void domainresolverTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    domainresolver_lstate_t *ls = lineGetState(l, t);
    ls->next_paused             = false;
    // The local DNS/order hold survives until its FIFO has actually drained.
    if (UNLIKELY(! domainresolverDrainPending(t, l)))
        return;
    discard domainresolverUpdateSourcePressure(t, l);
}
