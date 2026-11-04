#include "structure.h"

void tcpoverudpclientTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    tcpoverudpclient_lstate_t *ls = lineGetState(l, t);
    assert(ls->role == kTcpOverUdpClientTransport && ls->session != NULL);
    tcpoverudpclientSignalApplication(ls->session, tunnelPrevDownStreamPause);
}
