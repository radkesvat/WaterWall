#include "structure.h"

#include "loggers/network_logger.h"

void httpclientV2TunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    httpclient_lstate_t *ls = lineGetState(l, t);

    uint32_t len = 0;
    while ((len = sbufGetLength(buf)) > 0)
    {

        uint32_t consumed = min(1 << 15UL, len);

        nghttp2_ssize ret = nghttp2_session_mem_recv2(ls->session, (const uint8_t *) sbufGetRawPtr(buf), consumed);

        sbufShiftRight(buf, consumed);

        if (ret != (nghttp2_ssize) consumed)
        {
            // assert(false);
            bufferpoolReuseBuffer(lineGetBufferPool(l), buf);

            httpclientV2LinestateDestroy(ls);

            tunnelNextUpStreamFinish(t, l);
            tunnelPrevDownStreamFinish(t, l);

            return;
        }

        lineLock(l);

        if (! httpclientV2PullAndSendNgHttp2SendableData(t, ls))
        {
            bufferpoolReuseBuffer(lineGetBufferPool(l), buf);
            lineUnlock(l);
            return;
        }

        while (contextqueueLen(&ls->cq) > 0)
        {
            context_t *ctx = contextqueuePop(&ls->cq);
            contextApplyOnTunnelU(ctx, t);
            if (! lineIsAlive(l))
            {
                bufferpoolReuseBuffer(lineGetBufferPool(l), buf);
                lineUnlock(l);
                return;
            }
        }

        if (! httpclientV2PullAndSendNgHttp2SendableData(t, ls))
        {
            bufferpoolReuseBuffer(lineGetBufferPool(l), buf);
            lineUnlock(l);
            return;
        }

        while (contextqueueLen(&ls->cq_d) > 0)
        {
            context_t *ctx = contextqueuePop(&ls->cq_d);
            contextApplyOnPrevTunnelD(ctx, t);
            if (! lineIsAlive(l))
            {
                bufferpoolReuseBuffer(lineGetBufferPool(l), buf);
                lineUnlock(l);
                return;
            }
        }

        if (nghttp2_session_want_read(ls->session) == 0 && nghttp2_session_want_write(ls->session) == 0)
        {
            bufferpoolReuseBuffer(lineGetBufferPool(l), buf);
            httpclientV2LinestateDestroy(ls);

            tunnelNextUpStreamFinish(t, l);
            tunnelPrevDownStreamFinish(t, l);

            lineUnlock(l);
            return;
        }
        
        lineUnlock(l);
    }

    bufferpoolReuseBuffer(lineGetBufferPool(l), buf);
}
