#include "structure.h"

void wireguardclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *packet)
{
    assert(tunnelchainIsWorkerPacketLine(t->chain, l));
    discard l;

    wireguardclient_tstate_t *state = tunnelGetState(t);
    wireguardDispatch(&state->dispatch, 0, t, packet, NULL, wireguardclientSendInner, NULL);
}
