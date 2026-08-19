#include "structure.h"

#include "loggers/network_logger.h"

void blackholeTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    blackhole_tstate_t *state = tunnelGetState(t);
    assert(t->prev != NULL);

    if (state->mode == kBlackHoleModeActive)
    {
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    tunnelPrevDownStreamEst(t, l);
}
