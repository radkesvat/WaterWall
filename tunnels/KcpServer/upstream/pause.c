#include "structure.h"

void kcpserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    kcpserver_lstate_t *ls = lineGetState(l, t);
    assert(ls->kind == kKcpServerCarrier && ls->carrier != NULL);
    kcpserver_carrier_t *carrier = ls->carrier;
    kcpserverCarrierRetain(carrier);
    carrier->transport_paused = true;
    kcpserverRelayToServices(carrier, tunnelNextUpStreamPause, true);
    kcpserverCarrierRelease(carrier);
}
