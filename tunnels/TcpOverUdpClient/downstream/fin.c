#include "structure.h"

void tcpoverudpclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    tcpoverudpclient_lstate_t *ls = lineGetState(l, t);
    assert(ls->role == kTcpOverUdpClientTransport && ls->session != NULL);
    tcpoverudpclient_session_t *session = ls->session;
    session->transport_finished         = true;
    if (session->driver == NULL)
    {
        /* A local terminal callback is closing the separate application's owner.
         * This exact transport still has to die before its Finish returns. */
        tcpoverudpclientLinestateDestroy(ls);
        lineDestroy(l);
        return;
    }
    /* Abort settles synchronously even when a neighboring callback reenters the driver. */
    touSessionAbort(session->driver, kTouAborted);
}
