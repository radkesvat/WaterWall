#include "structure.h"

void wireguardclientTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    wireguardclient_tstate_t *state = tunnelGetState(t);
    if (state->carrier == l)
        state->paused = true;
}
