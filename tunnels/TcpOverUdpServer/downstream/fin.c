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
        if (lineIsAlive(l))
        {
            tunnelPrevDownStreamFinish(t, l);
        }
        lineUnref(l);
        return;
    }

    ls->can_upstream = false;

    uint8_t close_buf[kFrameHeaderLength] = {kFrameFlagClose};
    ikcp_send(ls->k_handle, (const char *) close_buf, (int) sizeof(close_buf));

    if (! tcpoverudpserverUpdateKcp(ls, true))
    {
        lineUnref(l);
        return;
    }

    tcpoverudpserverLinestateDestroy(ls);
    if (lineIsAlive(l))
    {
        tunnelPrevDownStreamFinish(t, l);
    }

    lineUnref(l);
}
