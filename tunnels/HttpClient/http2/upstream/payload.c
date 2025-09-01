#include "structure.h"

#include "loggers/network_logger.h"

void httpclientV2TunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    httpclient_lstate_t *ls = lineGetState(l, t);

    if (! ls->handshake_completed)
    {
        bufferqueuePushBack(&ls->bq, buf);
        return;
    }

    buffer_pool_t *pool = lineGetBufferPool(l);
    if (! httpclientV2PullAndSendNgHttp2SendableData(t, ls))
    {
        bufferpoolReuseBuffer(pool, buf);
        return;
    }

    tunnelNextUpStreamPayload(ls->tunnel, ls->line,
                              httpclientV2MakeFrame(ls->content_type == kApplicationGrpc, ls->stream_id, buf));
}
