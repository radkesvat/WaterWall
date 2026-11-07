#include "structure.h"

void kcpclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    kcpclient_lstate_t *ls = lineGetState(l, t);
    assert(ls->role == kKcpClientTransport && ls->session != NULL);
    kcpclientSetCarrierPaused(ls->session, false);
}
