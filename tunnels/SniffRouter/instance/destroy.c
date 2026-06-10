#include "structure.h"

void sniffrouterTunnelDestroy(tunnel_t *t)
{
    sniffrouter_tstate_t *ts = tunnelGetState(t);
    sniffrouterRouteTableDestroy(ts);
    reverseclientHandshakeDestroy(ts->reverse_handshake_bytes);
    tunnelDestroy(t);
}
