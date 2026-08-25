#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    tcpoverudpclient_lstate_t *ls = lineGetState(l, t);

    assert(ls->k_handle != NULL);

    lineRef(l);

    tcpoverudpclient_tstate_t *state = tunnelGetState(t);
    if (UNLIKELY(atomicLoadRelaxed(&state->stopping)))
    {
        tcpoverudpclientLinestateDestroy(ls);
        if (lineIsAlive(l))
        {
            tunnelNextUpStreamFinish(t, l);
        }
        lineUnref(l);
        return;
    }

    ls->can_downstream = false;

    uint8_t close_buf[kFrameHeaderLength] = {kFrameFlagClose};
    ikcp_send(ls->k_handle, (const char *) close_buf, (int) sizeof(close_buf));

    if (! tcpoverudpclientUpdateKcp(ls, true))
    {
        lineUnref(l);
        return;
    }

    tcpoverudpclientLinestateDestroy(ls);
    if (lineIsAlive(l))
    {
        tunnelNextUpStreamFinish(t, l);
    }

    lineUnref(l);
}
