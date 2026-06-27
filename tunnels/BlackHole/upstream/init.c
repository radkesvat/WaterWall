#include "structure.h"

#include "loggers/network_logger.h"

void blackholeTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    blackhole_tstate_t *state = tunnelGetState(t);

    if (state->mode == kBlackHoleModeActive)
    {
        if (t->prev != NULL)
        {
            tunnelPrevDownStreamFinish(t, l);
        }
        return;
    }

    if (t->prev != NULL)
    {
        tunnelPrevDownStreamEst(t, l);
    }
}
