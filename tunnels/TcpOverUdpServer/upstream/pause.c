#include "structure.h"

void tcpoverudpserverTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    tcpoverudpserver_lstate_t *ls = lineGetState(l, t);
    assert(ls->kind == kTcpOverUdpServerCarrier && ls->carrier != NULL);
    tcpoverudpserver_carrier_t *carrier = ls->carrier;
    tcpoverudpserverCarrierRetain(carrier);
    carrier->transport_paused = true;
    tcpoverudpserverRelayToServices(carrier, tunnelNextUpStreamPause, true);
    tcpoverudpserverCarrierRelease(carrier);
}
