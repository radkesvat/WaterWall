#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    tcpoverudpclient_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(GSTATE.application_stopping_flag))
    {
        tcpoverudpclientLinestateDestroy(ls);
        tunnelNextUpStreamFinish(t, l);
        return;
    }

    ls->can_downstream = false;

    uint8_t close_buf[kFrameHeaderLength] = {kFrameFlagClose};
    ikcp_send(ls->k_handle, (const char *) close_buf, (int) sizeof(close_buf));

    if (tcpoverudpclientUpdateKcp(ls, true))
    {
        tcpoverudpclientLinestateDestroy(ls);
        tunnelNextUpStreamFinish(t, l);
    }
    else
    {
        tcpoverudpclientLinestateDestroy(ls);
    }
}
