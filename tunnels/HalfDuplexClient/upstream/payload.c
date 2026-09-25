#include "structure.h"

bool halfduplexclientForwardPayload(tunnel_t *t, line_t *main, sbuf_t *buf)
{
    halfduplexclient_lstate_t *ls = lineGetState(main, t);
    if (LIKELY(ls->first_packet_sent))
        return lineCallWithRefWithBuf(ls->upload_line, tunnelNextUpStreamPayload, t, buf);

    line_t *upload   = ls->upload_line;
    line_t *download = ls->download_line;
    lineRef(main);
    lineRef(upload);
    lineRef(download);
    buffer_pool_t *pool    = lineGetBufferPool(main);
    const uint16_t padding = bufferpoolGetLargeBufferPadding(pool);
    uint32_t       length  = sbufGetLength(buf);
    const uint64_t total   = (uint64_t) length + kHLFDIntroSize;
    sbuf_t        *framed  = bufferpoolTryGetBestFit(pool, total, padding);
    sbuf_t        *intro   = bufferpoolTryGetBestFit(pool, kHLFDIntroSize, padding);
    if (framed == NULL || intro == NULL || total > sbufGetMaximumWriteableSize(framed) ||
        kHLFDIntroSize > sbufGetMaximumWriteableSize(intro))
    {
        if (framed != NULL)
            bufferpoolReuseBuffer(pool, framed);
        if (intro != NULL)
            bufferpoolReuseBuffer(pool, intro);
        bufferpoolReuseBuffer(pool, buf);
        halfduplexclientClosePair(t, main, false, false);
    }
    else
    {
        uint8_t pair_id[kHLFDPairIdSize];
        PUT_BE64(pair_id, fastRand64());
        PUT_BE64(pair_id + kHLFDPairIdSize / 2, fastRand64());
        uint8_t *wire = sbufGetMutablePtr(intro);
        wire[0]       = kHLFDCmdDownload;
        memoryCopy(wire + kHLFDPairIdOffset, pair_id, kHLFDPairIdSize);
        sbufSetLength(intro, kHLFDIntroSize);
        wire    = sbufGetMutablePtr(framed);
        wire[0] = kHLFDCmdUpload;
        memoryCopy(wire + kHLFDPairIdOffset, pair_id, kHLFDPairIdSize);
        sbufSetLength(framed, kHLFDIntroSize);
        if (sbufIsSplice(buf))
            sbufSpliceReadToBuffer(buf, framed, length);
        else
        {
            memoryCopyLarge(wire + kHLFDIntroSize, sbufGetRawPtr(buf), length);
            sbufSetLength(framed, (uint32_t) total);
        }
        lineReuseBuffer(main, buf);
        // Both intros exist before callbacks. Nested input queues behind the
        // older upload intro until this admitted first input has been submitted.
        ls->first_packet_sent = true;
        ls->intro_dispatching = true;
        tunnelNextUpStreamPayload(t, download, intro);
        if (halfduplexclientPairAlive(t, main, upload, download))
        {
            tunnelNextUpStreamPayload(t, upload, framed);
            if (halfduplexclientPairAlive(t, main, upload, download))
                ls->intro_dispatching = false;
        }
        else
            bufferpoolReuseBuffer(pool, framed);
    }
    bool alive = halfduplexclientPairAlive(t, main, upload, download);
    lineUnref(download);
    lineUnref(upload);
    lineUnref(main);
    return alive;
}

void halfduplexclientTunnelUpStreamPayload(tunnel_t *t, line_t *main, sbuf_t *buf)
{
    halfduplexclient_lstate_t *ls = lineGetState(main, t);
    if (UNLIKELY(ls->main_line == NULL))
    {
        lineReuseBuffer(main, buf);
        return;
    }
    if (ls->pair_initializing || ls->intro_dispatching || ls->draining || bufferqueueGetBufCount(&ls->pending_up) != 0)
    {
        size_t length = sbufGetLength(buf);
        if (UNLIKELY(length > kHalfDuplexClientMaxPendingBytes ||
                     bufferqueueGetBufLen(&ls->pending_up) > kHalfDuplexClientMaxPendingBytes - length ||
                     bufferqueueGetBufCount(&ls->pending_up) >= kHalfDuplexClientMaxPendingBuffers ||
                     ! bufferqueueTryPushBack(&ls->pending_up, &buf)))
        {
            lineReuseBuffer(main, buf);
            halfduplexclientClosePair(t, main, false, false);
            return;
        }
        discard halfduplexclientDrainPending(t, main, false);
        return;
    }
    // A ready path owns only this synchronous input. Its nested admissions may
    // complete after Pause; unrelated deferred Init input cannot join this path.
    lineRef(main);
    if (LIKELY(halfduplexclientForwardPayload(t, main, buf) && lineIsAlive(main) && ls->main_line == main))
        discard halfduplexclientDrainPending(t, main, true);
    lineUnref(main);
}
