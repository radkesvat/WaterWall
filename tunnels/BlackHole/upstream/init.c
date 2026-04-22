#include "structure.h"

#include "loggers/network_logger.h"

void blackholeTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    blackhole_tstate_t *state = tunnelGetState(t);

    if (state->mode == kBlackHoleModeActive)
    {
        tunnelPrevDownStreamFinish(t, l);
        return;
    }
    if (t->next == NULL)
    {
        return;
    }

    tunnelNextUpStreamInit(t, l);
}
