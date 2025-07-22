#include "structure.h"

#include "loggers/network_logger.h"

void bridgeTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    bridge_tstate_t *state = tunnelGetState(t);

    tunnelPrevDownStreamEst(state->pair_tun, l);
}
