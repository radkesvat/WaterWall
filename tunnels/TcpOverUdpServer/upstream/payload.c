#include "structure.h"

void tcpoverudpserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tcpoverudpserver_lstate_t *ls = lineGetState(l, t);
    assert(ls->kind == kTcpOverUdpServerCarrier && ls->carrier != NULL);
    tcpoverudpserverCarrierInput(ls->carrier, buf);
}
