#include "structure.h"

#include "loggers/network_logger.h"

void bgp4serverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    bgp4server_lstate_t *ls = lineGetState(l, t);

    buffer_pool_t *pool           = lineGetBufferPool(l);
    const uint64_t delivery_limit = max(UINT64_C(65536), 2 * (uint64_t) bufferpoolGetLargeBufferSize(pool));
    uint32_t       capacity;
    if (! sbufTryComputeCapacity((uint64_t) sbufGetLength(buf) + bufferstreamGetBufLen(&ls->read_stream),
                                 bufferpoolGetLargeBufferPadding(pool),
                                 &capacity) ||
        (uint64_t) sbufGetLength(buf) + bufferstreamGetBufLen(&ls->read_stream) >
            delivery_limit + kBgp4ServerFrameHeaderSize + kBgp4ServerMaxBodyLength)
    {
        bufferpoolReuseBuffer(pool, buf);
        bgp4serverCloseLine(t, l);
        return;
    }
    bufferstreamPush(&ls->read_stream, buf);
    sbuf_t *batch =
        bufferpoolTryGetBestFit(pool, bufferstreamGetBufLen(&ls->read_stream), bufferpoolGetLargeBufferPadding(pool));
    if (batch == NULL)
    {
        bgp4serverCloseLine(t, l);
        return;
    }

    while (true)
    {
        sbuf_t *body = NULL;
        if (! bgp4serverReadFrame(t, l, &ls->read_stream, &body))
        {
            if (batch != NULL)
                bufferpoolReuseBuffer(pool, batch);
            bgp4serverCloseLine(t, l);
            return;
        }

        if (body == NULL)
        {
            break;
        }

        if (! bgp4serverStripUpstreamBody(t, l, ls, body))
        {
            if (batch != NULL)
                bufferpoolReuseBuffer(pool, batch);
            bgp4serverCloseLine(t, l);
            return;
        }

        sbufMoveTo(batch, body, sbufGetLength(body));
        bufferpoolReuseBuffer(pool, body);
    }
    if (sbufGetLength(batch) == 0)
    {
        bufferpoolReuseBuffer(pool, batch);
        return;
    }
    if (batch != NULL)
    {
        tunnelNextUpStreamPayload(t, l, batch);
    }
}
