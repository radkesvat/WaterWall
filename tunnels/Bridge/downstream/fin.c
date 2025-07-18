#include "structure.h"

#include "loggers/network_logger.h"

void bridgeTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    bridge_tstate_t *state = tunnelGetState(t);

    tunnelNextUpStreamFinish(state->pair, l);
}
