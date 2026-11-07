#include "structure.h"

void kcpclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    kcpclient_lstate_t *ls = lineGetState(l, t);
    assert(ls->role == kKcpClientTransport && ls->session != NULL);
    kcpclientSignalApplication(ls->session, tunnelPrevDownStreamEst);
}
