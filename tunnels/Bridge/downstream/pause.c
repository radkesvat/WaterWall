#include "structure.h"

#include "loggers/network_logger.h"

void bridgeTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    bridge_tstate_t *state = tunnelGetState(t);

    tunnelNextUpStreamPause(state->pair_tun, l);
}
