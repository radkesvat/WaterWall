#include "structure.h"

void kcpclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    kcpclient_lstate_t *ls = lineGetState(l, t);
    assert(ls->role == kKcpClientApplication && ls->session != NULL);
    touSessionSend(ls->session->driver, buf);
}
