#include "structure.h"

#include "loggers/network_logger.h"

void halfduplexserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    halfduplexserver_lstate_t *ls = lineGetState(l, t);

    if (LIKELY(ls->download_line != NULL))
    {
        tunnelPrevDownStreamPayload(t, ls->download_line, buf);
    }
    else
    {
        bufferpoolReuseBuffer(lineGetBufferPool(l), buf);
    }
}
