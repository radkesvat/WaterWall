#include "structure.h"

void tcpoverudpserverTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    tcpoverudpserver_lstate_t *ls = lineGetState(l, t);
    assert(ls->kind == kTcpOverUdpServerCarrier && ls->carrier != NULL);
    tcpoverudpserver_carrier_t *carrier = ls->carrier;
    tcpoverudpserverCarrierRetain(carrier);
    carrier->transport_paused = false;
    tcpoverudpserverRelayToServices(carrier, tunnelNextUpStreamResume, true);
    tcpoverudpserverCarrierRelease(carrier);
}
