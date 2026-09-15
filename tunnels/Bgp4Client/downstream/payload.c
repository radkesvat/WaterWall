#include "structure.h"

#include "loggers/network_logger.h"

void bgp4clientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    bgp4client_lstate_t *ls = lineGetState(l, t);

    buffer_pool_t *pool           = lineGetBufferPool(l);
    const uint64_t delivery_limit = max(UINT64_C(65536), 2 * (uint64_t) bufferpoolGetLargeBufferSize(pool));
    uint32_t       capacity;
    if (! sbufTryComputeCapacity((uint64_t) sbufGetLength(buf) + bufferstreamGetBufLen(&ls->read_stream),
                                 bufferpoolGetLargeBufferPadding(pool),
                                 &capacity) ||
        (uint64_t) sbufGetLength(buf) + bufferstreamGetBufLen(&ls->read_stream) >
            delivery_limit + kBgp4ClientFrameHeaderSize + kBgp4ClientMaxBodyLength)
    {
        bufferpoolReuseBuffer(pool, buf);
        bgp4clientCloseLine(t, l);
        return;
    }
    bufferstreamPush(&ls->read_stream, buf);
    sbuf_t *batch =
        bufferpoolTryGetBestFit(pool, bufferstreamGetBufLen(&ls->read_stream), bufferpoolGetLargeBufferPadding(pool));
    if (batch == NULL)
    {
        bgp4clientCloseLine(t, l);
        return;
    }

    while (true)
    {
        sbuf_t *payload = NULL;
        if (! bgp4clientReadFrame(t, l, &ls->read_stream, &payload))
        {
            if (batch != NULL)
                bufferpoolReuseBuffer(pool, batch);
            bgp4clientCloseLine(t, l);
            return;
        }

        if (payload == NULL)
        {
            break;
        }

        if (sbufGetLength(batch) == 0)
            sbufTransferLifetime(payload, batch);
        sbufMoveTo(batch, payload, sbufGetLength(payload));
        bufferpoolReuseBuffer(pool, payload);
    }
    if (sbufGetLength(batch) == 0)
    {
        bufferpoolReuseBuffer(pool, batch);
        return;
    }
    if (batch != NULL)
    {
        tunnelPrevDownStreamPayload(t, l, batch);
    }
}
