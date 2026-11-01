#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    tcpoverudpserver_lstate_t *ls = lineGetState(l, t);

    assert(ls->k_handle != NULL);

    lineRef(l);

    tcpoverudpserver_tstate_t *state = tunnelGetState(t);
    if (UNLIKELY(atomicLoadRelaxed(&state->stopping)))
    {
        tcpoverudpserverLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        lineUnref(l);
        return;
    }

    ls->can_upstream = false;

    if (ikcp_waitsnd(ls->k_handle) > 0)
    {
        // Destroying the KCP state now would discard queued data that one flush cannot send, such as the
        // end of a large response; the KCP timer closes once the peer has acknowledged all of it.
        ls->closing = true;
        lineUnref(l);
        return;
    }

    tcpoverudpserverSendCloseAndFinish(ls);

    lineUnref(l);
}
