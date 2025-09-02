#include "structure.h"

#include "loggers/network_logger.h"

void httpserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{

    httpserver_lstate_t *ls = lineGetState(l, t);

    buffer_pool_t *pool = lineGetBufferPool(l);
    if (! httpserverV2PullAndSendNgHttp2SendableData(t, ls))
    {
        bufferpoolReuseBuffer(pool, buf);
        return;
    }

    tunnelPrevDownStreamPayload(ls->tunnel, ls->line,
                                httpserverV2MakeFrame(ls->content_type == kApplicationGrpc, ls->stream_id, buf));
}
