#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    tcpoverudpserver_lstate_t *ls = lineGetState(l, t);

    if (UNLIKELY(GSTATE.application_stopping_flag))
    {
        tcpoverudpserverLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    ls->can_upstream = false;

    uint8_t close_buf[kFrameHeaderLength] = {kFrameFlagClose};
    ikcp_send(ls->k_handle, (const char *) close_buf, (int) sizeof(close_buf));

    if (tcpoverudpserverUpdateKcp(ls, true))
    {
        tcpoverudpserverLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
    }
    else
    {
        tcpoverudpserverLinestateDestroy(ls);
    }
}
