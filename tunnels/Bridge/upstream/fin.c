#include "structure.h"

#include "loggers/network_logger.h"

void bridgeTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    bridge_tstate_t *state = tunnelGetState(t);

    tunnelPrevDownStreamFinish(state->pair, l);
}
