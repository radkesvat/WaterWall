#include "structure.h"

void kcpclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    kcpclient_lstate_t *ls = lineGetState(l, t);
    assert(ls->role == kKcpClientTransport && ls->session != NULL);
    kcpclient_session_t *session = ls->session;
    session->transport_finished  = true;
    if (session->driver == NULL)
    {
        /* A local terminal callback is closing the separate application's owner.
         * This exact transport still has to die before its Finish returns. */
        kcpclientLinestateDestroy(ls);
        lineDestroy(l);
        return;
    }
    /* Abort settles synchronously even when a neighboring callback reenters the driver. */
    touSessionAbort(session->driver, kTouAborted);
}
