#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{

    tcpoverudpserver_lstate_t *ls = lineGetState(l, t);

    ikcp_input(ls->k_handle, (void *) sbufGetMutablePtr(buf), (int) sbufGetLength(buf));

    bufferpoolReuseBuffer(lineGetBufferPool(l), buf);


    sbuf_t* large_buf = bufferpoolGetLargeBuffer(lineGetBufferPool(l));


    int read = ikcp_recv(ls->k_handle, (void *) sbufGetMutablePtr(large_buf), (int) sbufGetRightCapacity(large_buf));


    if (read > 0)
    {
        sbufSetLength(large_buf, (uint32_t) read);
        tunnelNextUpStreamPayload(t, l, large_buf);
    }
    else
    {
        bufferpoolReuseBuffer(lineGetBufferPool(l), large_buf);
    }
}
