#include "structure.h"

static void clientSignalTransport(tunnel_t *t, line_t *l, LineTaskFnNoBuf signal)
{
    tcpoverudpclient_lstate_t *ls = lineGetState(l, t);
    assert(ls->role == kTcpOverUdpClientApplication && ls->session != NULL);
    line_t *transport = ls->session->transport;
    lineRef(transport);
    signal(t, transport);
    lineUnref(transport);
}

void tcpoverudpclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    clientSignalTransport(t, l, tunnelNextUpStreamPause);
}

void tcpoverudpclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    clientSignalTransport(t, l, tunnelNextUpStreamResume);
}
