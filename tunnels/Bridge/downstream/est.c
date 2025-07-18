#include "structure.h"

#include "loggers/network_logger.h"

void bridgeTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    bridge_tstate_t *state = tunnelGetState(t);

    tunnelNextUpStreamEst(state->pair, l);
}
