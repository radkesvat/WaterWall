#include "structure.h"

#include "loggers/network_logger.h"

void bridgeTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    bridge_tstate_t *state = tunnelGetState(t);

    tunnelPrevDownStreamPayload(state->pair_tunel, l, buf);
}
