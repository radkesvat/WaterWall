#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    tcpoverudpclient_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(ls->k_handle == NULL))
    {
        return;
    }

    lineLock(l);

    if (UNLIKELY(signalmanagerIsTerminating()))
    {
        tcpoverudpclientLinestateDestroy(ls);
        if (lineIsAlive(l))
        {
            tunnelNextUpStreamFinish(t, l);
        }
        lineUnlock(l);
        return;
    }

    ls->can_downstream = false;

    uint8_t close_buf[kFrameHeaderLength] = {kFrameFlagClose};
    ikcp_send(ls->k_handle, (const char *) close_buf, (int) sizeof(close_buf));

    if (! tcpoverudpclientUpdateKcp(ls, true))
    {
        lineUnlock(l);
        return;
    }

    tcpoverudpclientLinestateDestroy(ls);
    if (lineIsAlive(l))
    {
        tunnelNextUpStreamFinish(t, l);
    }

    lineUnlock(l);
}
