#include "structure.h"

static void clientSignalTransport(tunnel_t *t, line_t *l, LineTaskFnNoBuf signal)
{
    kcpclient_lstate_t *ls = lineGetState(l, t);
    assert(ls->role == kKcpClientApplication && ls->session != NULL);
    line_t *transport = ls->session->transport;
    lineRef(transport);
    signal(t, transport);
    lineUnref(transport);
}

void kcpclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    clientSignalTransport(t, l, tunnelNextUpStreamPause);
}

void kcpclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    clientSignalTransport(t, l, tunnelNextUpStreamResume);
}
