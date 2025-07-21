#include "structure.h"

#include "loggers/network_logger.h"

void bridgeTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    bridge_tstate_t *state = tunnelGetState(t);

    tunnelNextUpStreamResume(state->pair_tunel, l);
}
