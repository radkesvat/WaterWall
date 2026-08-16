#include "structure.h"

void sniffrouterTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard               context;
    sniffrouter_tstate_t *ts = tunnelGetState(t);
    sniffrouterRouteTableDestroy(ts);
    reverseclientHandshakeDestroy(ts->reverse_handshake_bytes);
    tunnelDestroy(t);
}
