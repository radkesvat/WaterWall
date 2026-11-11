#include "loggers/network_logger.h"
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
    // Ordinary headroom also proves that the prepended length fits its uint32_t capacity.
    const bool     reuse   = ! sbufIsSplice(buf) && sbufGetHeadroom(buf) >= kHLFDIntroSize;
    sbuf_t        *framed  = reuse ? buf : bufferpoolTryGetBestFit(pool, total, padding);
    if (framed == NULL)
    {
        LOGW("HalfDuplexClient: closing pair: upload intro allocation geometry refused "
             "(payload_bytes=%u, intro_bytes=%u, requested_bytes=%" PRIu64 ")",
             length,
             (unsigned) kHLFDIntroSize,
             total);
        bufferpoolReuseBuffer(pool, buf);
        halfduplexclientClosePair(t, main, false, false);
    }
    else
    {
        sbuf_t *intro = bufferpoolGetBestFit(pool, kHLFDIntroSize, padding);
        uint8_t pair_id[kHLFDPairIdSize];
        PUT_BE64(pair_id, fastRand64());
        PUT_BE64(pair_id + kHLFDPairIdSize / 2, fastRand64());
        uint8_t *wire = sbufGetMutablePtr(intro);
        wire[0]       = kHLFDCmdDownload;
        memoryCopy(wire + kHLFDPairIdOffset, pair_id, kHLFDPairIdSize);
        sbufSetLength(intro, kHLFDIntroSize);
        if (reuse)
            sbufShiftLeft(framed, kHLFDIntroSize);
        wire    = sbufGetMutablePtr(framed);
        wire[0] = kHLFDCmdUpload;
        memoryCopy(wire + kHLFDPairIdOffset, pair_id, kHLFDPairIdSize);
        if (! reuse)
        {
            sbufSetLength(framed, kHLFDIntroSize);
            // Append after the intro in the reserved output; sbufEnsureOrdinary()
            // would allocate a separate temporary buffer for splice input.
            if (sbufIsSplice(buf))
                sbufSpliceReadToBuffer(buf, framed, length);
            else
            {
                memoryCopyLarge(wire + kHLFDIntroSize, sbufGetRawPtr(buf), length);
                sbufSetLength(framed, total);
            }
            lineReuseBuffer(main, buf);
        }
        // Both intros exist before callbacks. Nested input queues behind the
        // older upload intro until this admitted first input has been submitted.
        ls->intro_dispatching = true;
        tunnelNextUpStreamPayload(t, download, intro);
        if (halfduplexclientPairAlive(t, main, upload, download))
        {
            // Both intros have reached their transports once this callback starts.
            ls->first_packet_sent = true;
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
    if (UNLIKELY(ls->main_line == NULL || (ls->first_packet_sent && ls->upload_line == NULL)))
    {
        lineReuseBuffer(main, buf);
        return;
    }
    if (ls->pair_initializing || ls->intro_dispatching || ls->draining ||
        bufferqueueGetEntryCount(&ls->pending_up) != 0)
    {
        size_t length = sbufGetLength(buf);
        if (UNLIKELY(length > kHalfDuplexClientMaxPendingBytes ||
                     bufferqueueGetLength(&ls->pending_up) > kHalfDuplexClientMaxPendingBytes - length ||
                     bufferqueueGetCharge(&ls->pending_up) > kHalfDuplexClientMaxPendingCharge ||
                     sbufGetQueueCharge(buf) >
                         kHalfDuplexClientMaxPendingCharge - bufferqueueGetCharge(&ls->pending_up) ||
                     ! bufferqueueTryPushBack(&ls->pending_up, &buf)))
        {
            const size_t pending_bytes   = bufferqueueGetLength(&ls->pending_up);
            const size_t pending_charge  = bufferqueueGetCharge(&ls->pending_up);
            const size_t incoming_charge = sbufGetQueueCharge(buf);
            LOGW("HalfDuplexClient: closing pair: pending upstream %s "
                 "(pending_bytes=%zu, incoming_bytes=%zu, byte_limit=%u, pending_charge_bytes=%zu, "
                 "incoming_charge_bytes=%zu, charge_limit_bytes=%u)",
                 length > kHalfDuplexClientMaxPendingBytes || pending_bytes > kHalfDuplexClientMaxPendingBytes - length
                     ? "byte limit exceeded"
                 : pending_charge > kHalfDuplexClientMaxPendingCharge ||
                         incoming_charge > kHalfDuplexClientMaxPendingCharge - pending_charge
                     ? "storage charge limit exceeded"
                     : "queue admission failed",
                 pending_bytes,
                 length,
                 (unsigned) kHalfDuplexClientMaxPendingBytes,
                 pending_charge,
                 incoming_charge,
                 (unsigned) kHalfDuplexClientMaxPendingCharge);
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
