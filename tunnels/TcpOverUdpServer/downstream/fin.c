#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    tcpoverudpserver_lstate_t *ls = lineGetState(l, t);

    ls->can_upstream = false;

    sbuf_t *fin_buf = bufferpoolGetSmallBuffer(lineGetBufferPool(l));

    sbufSetLength(fin_buf, kFrameHeaderLength);
    sbufWriteUI8(fin_buf, kFrameFlagClose);
    ikcp_send(ls->k_handle, (void *) sbufGetMutablePtr(fin_buf), (int) sbufGetLength(fin_buf));

    bufferpoolReuseBuffer(lineGetBufferPool(l), fin_buf);

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
