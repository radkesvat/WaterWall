#include "structure.h"

#include "loggers/network_logger.h"

void bridgeTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    bridge_tstate_t *state = tunnelGetState(t);

    tunnelNextUpStreamInit(state->pair_tunel, l);
}
