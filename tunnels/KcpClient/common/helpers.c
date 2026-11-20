#include "structure.h"

static void clientSetReadHold(tunnel_t *t, line_t *l, bool paused)
{
    kcpclient_lstate_t *ls = lineGetState(l, t);
    assert(ls->role == kKcpClientApplication && ls->session != NULL);
    ls->session->application_read_hold = paused;
    line_t *transport                  = ls->session->transport;
    lineRef(transport);
    if (paused)
        tunnelNextUpStreamPause(t, transport);
    else
        tunnelNextUpStreamResume(t, transport);
    lineUnref(transport);
}

void kcpclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    clientSetReadHold(t, l, true);
}

void kcpclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    clientSetReadHold(t, l, false);
}
