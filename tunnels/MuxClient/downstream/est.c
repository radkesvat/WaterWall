#include "structure.h"

#include "loggers/network_logger.h"

void muxclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    muxclient_tstate_t *ts = tunnelGetState(t);
    muxclient_lstate_t *ls = lineGetState(l, t);
    assert(! ls->is_child && ls->parent_state != NULL);
    muxclient_parent_state_t *state = ls->parent_state;
    if (state->transport_established)
        return;
    state->transport_established = true;
    state->next_ping_at_ms       = wloopNowMonotonicMS(getWorkerLoop(lineGetWID(l))) + ts->ping_interval_ms;
    muxclientArmKeepalive(t, ls);
    if (! lineIsEstablished(l))
        lineMarkEstablished(l);
}
