#include "structure.h"

void kcpclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    kcpclient_lstate_t *ls = lineGetState(l, t);
    assert(ls->role == kKcpClientTransport && ls->session != NULL);
    if (ls->session->driver == NULL)
    {
        lineReuseBuffer(l, buf);
        return;
    }
    touSessionInput(ls->session->driver, buf);
}
