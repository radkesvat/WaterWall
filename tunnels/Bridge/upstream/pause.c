#include "structure.h"

#include "loggers/network_logger.h"

void bridgeTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    bridge_tstate_t *state = tunnelGetState(t);

    tunnelPrevDownStreamPause(state->pair_tunel, l);
}
