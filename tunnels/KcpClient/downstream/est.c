#include "structure.h"

void kcpclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    kcpclient_lstate_t *ls = lineGetState(l, t);
    assert(ls->role == kKcpClientTransport && ls->session != NULL);
    kcpclient_session_t *session = ls->session;
    if (session->application == NULL || session->application_est_delivered)
        return;
    session->application_est_delivered = true;
    kcpclientSignalApplication(session, tunnelPrevDownStreamEst);
}
