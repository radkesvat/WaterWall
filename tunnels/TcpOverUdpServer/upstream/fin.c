#include "structure.h"

void tcpoverudpserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    tcpoverudpserver_lstate_t *ls = lineGetState(l, t);
    assert(ls->kind == kTcpOverUdpServerCarrier && ls->carrier != NULL);
    /* Never reflect Finish toward the borrowed carrier's owner. */
    tcpoverudpserverCarrierClose(ls->carrier, false);
}
