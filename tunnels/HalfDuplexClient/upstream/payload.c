#include "loggers/network_logger.h"
#include "structure.h"

static bool frameIntro(line_t *child, sbuf_t *input, sbuf_t **upload, sbuf_t **download)
{
    buffer_pool_t *pool    = lineGetBufferPool(child);
    const uint16_t padding = bufferpoolGetLargeBufferPadding(pool);
    uint32_t       length  = sbufGetLength(input);
    const uint64_t total   = (uint64_t) length + kHLFDIntroSize;
    const bool     reuse   = ! sbufIsSplice(input) && sbufGetHeadroom(input) >= kHLFDIntroSize;
    sbuf_t        *framed  = reuse ? input : bufferpoolTryGetBestFit(pool, total, padding);
    if (framed == NULL)
    {
        LOGW("HalfDuplexClient: closing pair: upload intro allocation geometry refused "
             "(payload_bytes=%u, intro_bytes=%u, requested_bytes=%" PRIu64 ")",
             length,
             (unsigned) kHLFDIntroSize,
             total);
        bufferpoolReuseBuffer(pool, input);
        return false;
    }

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
        if (sbufIsSplice(input))
            sbufSpliceReadToBuffer(input, framed, length);
        else
        {
            memoryCopyLarge(wire + kHLFDIntroSize, sbufGetRawPtr(input), length);
            sbufSetLength(framed, total);
        }
        bufferpoolReuseBuffer(pool, input);
    }
    *upload   = framed;
    *download = intro;
    return true;
}

void halfduplexclientPump(halfduplexclient_pair_t *pair, sbuf_t *direct)
{
    halfduplexclient_tstate_t *ts = tunnelGetState(pair->tunnel);
    if (direct != NULL && pair->intro == kHalfDuplexUploadIntroSent)
    {
        // Established traffic can reenter directly without the startup FIFO's
        // size limit. Finish waits until every active upload handoff returns.
        ++pair->refs;
        ++pair->handoff_depth;
        discard lineCallWithRefWithBuf(pair->upload, tunnelUpStreamPayload, ts->upload_tunnel, direct);
        --pair->handoff_depth;
        if (pair->main == NULL || bufferqueueGetEntryCount(&pair->pending) != 0)
            halfduplexclientPump(pair, NULL);
        halfduplexclientReleasePair(pair);
        return;
    }
    if (pair->pumping || pair->starting || pair->ending || pair->handoff_depth != 0)
    {
        assert(direct == NULL);
        return;
    }
    // A ready input and its nested first-intro batch may finish under advisory
    // Pause. Startup backlog and a detached drain wait for receiver permission.
    const bool admitted = direct != NULL;
    ++pair->refs;
    pair->pumping = true;
    while (! pair->ending)
    {
        const bool closing = pair->main == NULL;
        if (closing)
        {
            if (closeDrainTimeRemaining(&pair->deadline) == 0 || ! wloopNormalDispatchAllowed(getCurrentWorkerLoop()))
            {
                halfduplexclientEndPair(pair, "close drain deadline or worker admission ended");
                break;
            }
            if (pair->download != NULL && pair->download_read_paused)
            {
                pair->download_read_paused = false;
                discard lineCallWithRef(pair->download, tunnelUpStreamResume, ts->download_tunnel);
                continue;
            }
        }
        if (pair->upload == NULL)
            break;
        if (direct == NULL && pair->upload_intro == NULL && bufferqueueGetEntryCount(&pair->pending) == 0)
        {
            if (closing)
                halfduplexclientCloseChild(pair, &pair->upload, true);
            break;
        }
        const bool send_download_intro = pair->intro == kHalfDuplexIntroPending;
        if (closing)
        {
            if (send_download_intro ? pair->download_paused : pair->upload_paused)
                break;
        }
        else if (! admitted && pair->upload_intro == NULL && (pair->upload_paused || pair->download_paused))
            break;

        sbuf_t *buf        = pair->upload_intro;
        pair->upload_intro = NULL;
        if (buf == NULL)
        {
            buf    = direct != NULL ? direct : bufferqueuePopFront(&pair->pending);
            direct = NULL;
        }
        if (send_download_intro)
        {
            sbuf_t *intro;
            if (! frameIntro(pair->upload, buf, &pair->upload_intro, &intro))
            {
                halfduplexclientEndPair(pair, closing ? "could not frame the upload intro" : NULL);
                break;
            }
            // Both copies and the first body are owned before either callback.
            pair->intro = kHalfDuplexDownloadIntroSent;
            discard lineCallWithRefWithBuf(pair->download, tunnelUpStreamPayload, ts->download_tunnel, intro);
        }
        else
        {
            pair->intro = kHalfDuplexUploadIntroSent;
            discard lineCallWithRefWithBuf(pair->upload, tunnelUpStreamPayload, ts->upload_tunnel, buf);
        }
    }
    pair->pumping = false;
    if (! pair->ending && pair->main == NULL)
    {
        if (pair->upload == NULL && pair->download == NULL)
            halfduplexclientEndPair(pair, NULL);
        else if (! closeDrainArm(&pair->deadline, getCurrentWorkerLoop()))
            halfduplexclientEndPair(pair, "close drain timer refused");
    }
    halfduplexclientReleasePair(pair);
}

void halfduplexclientTunnelUpStreamPayload(tunnel_t *t, line_t *main, sbuf_t *buf)
{
    halfduplexclient_pair_t *pair = halfduplexclientGetPair(t, main);
    if (pair == NULL || pair->ending || pair->upload == NULL)
    {
        lineReuseBuffer(main, buf);
        return;
    }
    if (pair->starting || pair->pumping || (pair->handoff_depth != 0 && pair->intro != kHalfDuplexUploadIntroSent) ||
        pair->upload_paused || pair->download_paused || bufferqueueGetEntryCount(&pair->pending) != 0)
    {
        size_t length = sbufGetLength(buf);
        if (UNLIKELY(length > kHalfDuplexClientMaxPendingBytes ||
                     bufferqueueGetLength(&pair->pending) > kHalfDuplexClientMaxPendingBytes - length ||
                     bufferqueueGetCharge(&pair->pending) > kHalfDuplexClientMaxPendingCharge ||
                     sbufGetQueueCharge(buf) >
                         kHalfDuplexClientMaxPendingCharge - bufferqueueGetCharge(&pair->pending) ||
                     ! bufferqueueTryPushBack(&pair->pending, &buf)))
        {
            const size_t pending_bytes   = bufferqueueGetLength(&pair->pending);
            const size_t pending_charge  = bufferqueueGetCharge(&pair->pending);
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
            halfduplexclientEndPair(pair, NULL);
            return;
        }
        buf = NULL;
    }
    halfduplexclientPump(pair, buf);
}
