#include "structure.h"

static void closeStream(tunnel_t *t, line_t *l)
{
    obfuscatorserverLinestateDestroy(lineGetState(l, t));
    tunnelNextUpStreamFinish(t, l);
    tunnelPrevDownStreamFinish(t, l);
}

void obfuscatorserverEncodeStream(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    buffer_pool_t *pool    = lineGetBufferPool(l);
    const uint32_t length  = sbufGetLength(buf);
    const uint64_t records = max(UINT64_C(1), ((uint64_t) length + 65534) / 65535);
    const uint64_t total   = length + 5 * records;
    sbuf_t        *out     = bufferpoolTryGetBestFit(pool, total, bufferpoolGetLargeBufferPadding(pool));
    if (! out || total > sbufGetMaximumWriteableSize(out))
    {
        if (out)
            bufferpoolReuseBuffer(pool, out);
        bufferpoolReuseBuffer(pool, buf);
        closeStream(t, l);
        return;
    }
    const uint32_t start = out->curpos;
    for (uint64_t record = 0; record < records; ++record)
    {
        const uint32_t n      = min(sbufGetLength(buf), UINT16_MAX);
        uint8_t       *header = sbufGetMutablePtr(out);
        header[0]             = 23;
        header[1]             = 3;
        header[2]             = 3;
        header[3]             = (uint8_t) (n >> 8);
        header[4]             = (uint8_t) n;
        out->curpos += 5;
        sbufSetLength(out, 0);
        sbufMoveTo(out, buf, n);
        obfuscatorserverApplyXor(t, l, out); /* Skip is computed for this record's plaintext. */
        out->curpos += n;
    }
    out->curpos = start;
    sbufSetLength(out, (uint32_t) total);
    sbufTransferLifetime(buf, out);
    bufferpoolReuseBuffer(pool, buf);
    tunnelNextUpStreamPayload(t, l, out);
}

void obfuscatorserverDrainStream(tunnel_t *t, line_t *l)
{
    obfuscatorserver_lstate_t *ls = lineGetState(l, t);
    if (ls->paused || bufferstreamGetBufLen(&ls->read_stream) < 5)
        return;
    buffer_pool_t *pool = lineGetBufferPool(l);
    sbuf_t        *out  = NULL;
    while (bufferstreamGetBufLen(&ls->read_stream) >= 5)
    {
        uint8_t header[5];
        bufferstreamViewBytesAt(&ls->read_stream, 0, header, 5);
        if (header[0] != 23 || header[1] != 3 || header[2] != 3)
        {
            if (out)
                bufferpoolReuseBuffer(pool, out);
            closeStream(t, l);
            return;
        }
        const uint32_t length = ((uint32_t) header[3] << 8) | header[4];
        if (bufferstreamGetBufLen(&ls->read_stream) < length + 5)
            break;
        const bool first_record = out == NULL;
        if (first_record)
        {
            out = bufferpoolTryGetBestFit(
                pool, bufferstreamGetBufLen(&ls->read_stream), bufferpoolGetLargeBufferPadding(pool));
            if (! out)
            {
                closeStream(t, l);
                return;
            }
        }
        sbuf_t *record = bufferstreamReadExact(&ls->read_stream, length + 5);
        sbufShiftRight(record, 5);
        obfuscatorserverApplyXor(t, l, record);
        if (first_record)
            sbufTransferLifetime(record, out);
        sbufMoveTo(out, record, length);
        bufferpoolReuseBuffer(pool, record);
    }
    if (out)
        tunnelPrevDownStreamPayload(t, l, out);
}

void obfuscatorserverDecodeStream(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    obfuscatorserver_lstate_t *ls        = lineGetState(l, t);
    buffer_pool_t             *pool      = lineGetBufferPool(l);
    const uint64_t             allowance = max(UINT64_C(65536), 2 * (uint64_t) bufferpoolGetLargeBufferSize(pool));
    const uint64_t             total     = (uint64_t) bufferstreamGetBufLen(&ls->read_stream) + sbufGetLength(buf);
    uint32_t                   capacity;
    if (total > allowance + 65540 || ! sbufTryComputeCapacity(total, bufferpoolGetLargeBufferPadding(pool), &capacity))
    {
        bufferpoolReuseBuffer(pool, buf);
        closeStream(t, l);
        return;
    }
    const uint32_t length = sbufGetLength(buf);
    if (length == 0)
    {
        bufferpoolReuseBuffer(pool, buf);
        return;
    }
    bufferstreamPush(&ls->read_stream, buf);
    obfuscatorserverDrainStream(t, l);
}
