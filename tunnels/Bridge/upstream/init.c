#include "structure.h"

#include "loggers/network_logger.h"

void bridgeTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    bridge_tstate_t *state = tunnelGetState(t);

    tunnelPrevDownStreamInit(state->pair_tun, l);
}
