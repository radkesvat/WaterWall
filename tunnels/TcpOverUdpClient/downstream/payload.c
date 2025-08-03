#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tcpoverudpclient_lstate_t *ls = lineGetState(l, t);

    ikcp_input(ls->k_handle, (void *) sbufGetMutablePtr(buf), (int) sbufGetLength(buf));

    sbufReset(buf);

    int read = ikcp_recv(ls->k_handle, (void *) sbufGetMutablePtr(buf), (int) sbufGetLength(buf));

    if (read > 0)
    {
        sbufSetLength(buf, (uint32_t) read);
        tunnelPrevDownStreamPayload(t, l, buf);
    }
    else
    {
        bufferpoolReuseBuffer(lineGetBufferPool(l), buf);
    }
}
