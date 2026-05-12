#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    tcpoverudpserver_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->k_handle == NULL))
    {
        return;
    }

    lineLock(l);

    if (UNLIKELY(GSTATE.application_stopping_flag))
    {
        tcpoverudpserverLinestateDestroy(ls);
        if (lineIsAlive(l))
        {
            tunnelPrevDownStreamFinish(t, l);
        }
        lineUnlock(l);
        return;
    }

    ls->can_upstream = false;

    uint8_t close_buf[kFrameHeaderLength] = {kFrameFlagClose};
    ikcp_send(ls->k_handle, (const char *) close_buf, (int) sizeof(close_buf));

    if (! tcpoverudpserverUpdateKcp(ls, true))
    {
        lineUnlock(l);
        return;
    }

    tcpoverudpserverLinestateDestroy(ls);
    if (lineIsAlive(l))
    {
        tunnelPrevDownStreamFinish(t, l);
    }

    lineUnlock(l);
}
