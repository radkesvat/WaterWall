#include "structure.h"

#include "loggers/network_logger.h"

void bridgeTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    bridge_tstate_t *state = tunnelGetState(t);

    tunnelNextUpStreamPayload(state->pair_tunel, l, buf);
}
