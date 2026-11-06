#include "structure.h"

void tcpoverudpclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    tcpoverudpclient_lstate_t *ls = lineGetState(l, t);
    assert(ls->role == kTcpOverUdpClientTransport && ls->session != NULL);
    tcpoverudpclientSetCarrierPaused(ls->session, false);
}
