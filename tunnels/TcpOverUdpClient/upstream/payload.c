#include "structure.h"

void tcpoverudpclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tcpoverudpclient_lstate_t *ls = lineGetState(l, t);
    assert(ls->role == kTcpOverUdpClientApplication && ls->session != NULL);
    touSessionSend(ls->session->driver, buf);
}
