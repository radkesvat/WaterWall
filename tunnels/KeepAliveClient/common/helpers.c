#include "structure.h"

#include "loggers/network_logger.h"

typedef enum keepaliveclient_consume_result_e
{
    kKeepAliveClientConsumeNeedMore = 0,
    kKeepAliveClientConsumeContinue,
    kKeepAliveClientConsumeLineDead
} keepaliveclient_consume_result_t;

static bool keepaliveclientIsPacketLine(tunnel_t *t, line_t *l)
{
    tunnel_chain_t *chain = tunnelGetChain(t);
    if (chain == NULL || chain->packet_lines == NULL)
    {
        return false;
    }

    return tunnelchainGetWorkerPacketLine(chain, lineGetWID(l)) == l;
}

static sbuf_t *keepaliveclientAllocFrameBuffer(buffer_pool_t *pool, uint32_t frame_len)
{
    if (frame_len <= bufferpoolGetSmallBufferSize(pool))
    {
        return bufferpoolGetSmallBuffer(pool);
    }

    if (frame_len <= bufferpoolGetLargeBufferSize(pool))
    {
        return bufferpoolGetLargeBuffer(pool);
    }

    return sbufCreateWithPadding(frame_len, bufferpoolGetLargeBufferPadding(pool));
}

static bool keepaliveclientSendFrameNext(tunnel_t *t, line_t *l, sbuf_t *buf, uint8_t frame_kind, uint32_t payload_len)
{
    const uint32_t frame_body_len = payload_len + kKeepAliveFrameTypeSize;
    const uint32_t frame_len      = frame_body_len + kKeepAliveFrameLengthSize;

    if (keepaliveclientIsPacketLine(t, l) && frame_len > kMaxAllowedPacketLength)
    {
        LOGE("KeepAliveClient: worker packet line payload exceeds kMaxAllowedPacketLength after framing: %u > %u",
             (unsigned int) frame_len,
             (unsigned int) kMaxAllowedPacketLength);
        lineReuseBuffer(l, buf);
        return true;
    }

    if (sbufGetLeftCapacity(buf) < kKeepAliveFramePrefixSize)
    {
        LOGW("KeepAliveClient: dropping frame because left padding is smaller than required header size");
        lineReuseBuffer(l, buf);
        return true;
    }

    if (sbufGetMaximumWriteableSize(buf) < frame_body_len)
    {
        buf = sbufReserveSpace(buf, frame_body_len);
    }

    sbufShiftLeft(buf, kKeepAliveFramePrefixSize);

    uint8_t *frame                  = sbufGetMutablePtr(buf);
    uint16_t frame_body_len_network = htons((uint16_t) frame_body_len);
    sbufByteCopy(frame, &frame_body_len_network, (uint32_t) sizeof(frame_body_len_network));
    frame[kKeepAliveFrameLengthSize] = frame_kind;

    sbufSetLength(buf, frame_len);
    return withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, buf);
}

static bool keepaliveclientSendControlFrame(tunnel_t *t, line_t *l, uint8_t frame_kind)
{
    if (! lineIsAlive(l))
    {
        return true;
    }

    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(l));
    sbufSetLength(buf, 0);
    return keepaliveclientSendFrameNext(t, l, buf, frame_kind, 0);
}

static keepaliveclient_consume_result_t keepaliveclientConsumeOneFrame(tunnel_t *t, line_t *l,
                                                                       keepaliveclient_lstate_t *ls)
{
    if (bufferstreamGetBufLen(&ls->read_stream) < kKeepAliveFramePrefixSize)
    {
        return kKeepAliveClientConsumeNeedMore;
    }

    uint8_t header[kKeepAliveFrameLengthSize];
    bufferstreamViewBytesAt(&ls->read_stream, 0, header, sizeof(header));

    uint16_t frame_body_len_network;
    sbufByteCopy(&frame_body_len_network, header, (uint32_t) sizeof(frame_body_len_network));
    uint16_t frame_body_len = ntohs(frame_body_len_network);

    if (frame_body_len < kKeepAliveFrameTypeSize)
    {
        LOGW("KeepAliveClient: invalid downstream keepalive frame length: %u", (unsigned int) frame_body_len);
        bufferstreamEmpty(&ls->read_stream);
        return kKeepAliveClientConsumeNeedMore;
    }

    if ((uint32_t) frame_body_len + kKeepAliveFrameLengthSize > (uint32_t) bufferstreamGetBufLen(&ls->read_stream))
    {
        return kKeepAliveClientConsumeNeedMore;
    }

    sbuf_t *frame = bufferstreamReadExact(&ls->read_stream, kKeepAliveFrameLengthSize + frame_body_len);
    sbufShiftRight(frame, kKeepAliveFrameLengthSize);

    const uint8_t  frame_kind  = sbufReadUI8(frame);
    const uint32_t payload_len = frame_body_len - kKeepAliveFrameTypeSize;

    switch (frame_kind)
    {
    case kKeepAliveFrameKindNormal:
        if (payload_len == 0)
        {
            LOGW("KeepAliveClient: dropping empty normal frame");
            lineReuseBuffer(l, frame);
            return kKeepAliveClientConsumeContinue;
        }

        sbufShiftRight(frame, kKeepAliveFrameTypeSize);
        if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, frame))
        {
            return kKeepAliveClientConsumeLineDead;
        }
        return kKeepAliveClientConsumeContinue;

    case kKeepAliveFrameKindPing:
        lineReuseBuffer(l, frame);
        if (! keepaliveclientSendControlFrame(t, l, kKeepAliveFrameKindPong))
        {
            return kKeepAliveClientConsumeLineDead;
        }
        return kKeepAliveClientConsumeContinue;

    case kKeepAliveFrameKindPong:
        lineReuseBuffer(l, frame);
        return kKeepAliveClientConsumeContinue;

    default:
        LOGW("KeepAliveClient: dropping unknown frame kind %u", (unsigned int) frame_kind);
        lineReuseBuffer(l, frame);
        return kKeepAliveClientConsumeContinue;
    }
}

void keepaliveclientTrackLine(tunnel_t *t, line_t *l)
{
    keepaliveclient_tstate_t *ts = tunnelGetState(t);
    keepaliveclient_lstate_t *ls = lineGetState(l, t);

    mutexLock(&ts->lines_mutex);

    ls->tracked_prev = NULL;
    ls->tracked_next = ts->lines_head;
    if (ts->lines_head != NULL)
    {
        ts->lines_head->tracked_prev = ls;
    }
    ts->lines_head = ls;

    mutexUnlock(&ts->lines_mutex);
}

void keepaliveclientUntrackLine(tunnel_t *t, line_t *l)
{
    keepaliveclient_tstate_t *ts = tunnelGetState(t);
    keepaliveclient_lstate_t *ls = lineGetState(l, t);

    mutexLock(&ts->lines_mutex);

    if (ls->tracked_prev != NULL)
    {
        ls->tracked_prev->tracked_next = ls->tracked_next;
    }
    else if (ts->lines_head == ls)
    {
        ts->lines_head = ls->tracked_next;
    }

    if (ls->tracked_next != NULL)
    {
        ls->tracked_next->tracked_prev = ls->tracked_prev;
    }

    ls->tracked_prev = NULL;
    ls->tracked_next = NULL;

    mutexUnlock(&ts->lines_mutex);
}

void keepaliveclientWorkerTimerCallback(wtimer_t *timer)
{
    tunnel_t *t = weventGetUserdata(timer);
    if (t == NULL || isApplicationTerminating())
    {
        return;
    }

    keepaliveclient_tstate_t *ts    = tunnelGetState(t);
    keepaliveclient_lstate_t *it    = NULL;
    line_t                  **lines = NULL;
    size_t                    count = 0;
    size_t                    index = 0;
    const wid_t               wid   = getWID();

    mutexLock(&ts->lines_mutex);

    for (it = ts->lines_head; it != NULL; it = it->tracked_next)
    {
        if (it->wid == wid && it->line != NULL)
        {
            count += 1;
        }
    }

    if (count > 0)
    {
        lines = memoryAllocate(sizeof(line_t *) * count);
        for (it = ts->lines_head; it != NULL; it = it->tracked_next)
        {
            if (it->wid == wid && it->line != NULL)
            {
                lines[index++] = it->line;
            }
        }
    }

    mutexUnlock(&ts->lines_mutex);

    for (size_t i = 0; i < count; ++i)
    {
        if (! lineIsAlive(lines[i]))
        {
            continue;
        }

        discard keepaliveclientSendPingFrame(t, lines[i]);
    }

    if (lines != NULL)
    {
        memoryFree(lines);
    }
}

bool keepaliveclientSendPingFrame(tunnel_t *t, line_t *l)
{
    return keepaliveclientSendControlFrame(t, l, kKeepAliveFrameKindPing);
}

bool keepaliveclientSendNormalFrameUpstream(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    const uint32_t payload_len = sbufGetLength(buf);

    if (payload_len == 0)
    {
        lineReuseBuffer(l, buf);
        return true;
    }

    if (keepaliveclientIsPacketLine(t, l) && payload_len + kKeepAliveFramePrefixSize > kMaxAllowedPacketLength)
    {
        LOGE("KeepAliveClient: worker packet line payload exceeds kMaxAllowedPacketLength after framing: %u > %u",
             (unsigned int) (payload_len + kKeepAliveFramePrefixSize),
             (unsigned int) kMaxAllowedPacketLength);
        lineReuseBuffer(l, buf);
        return true;
    }

    if (payload_len > kKeepAliveMaxPayloadChunkSize)
    {
        buffer_pool_t *pool      = lineGetBufferPool(l);
        const uint8_t *src       = sbufGetRawPtr(buf);
        uint32_t       remaining = payload_len;

        while (remaining > 0)
        {
            const uint32_t chunk_len = min(remaining, (uint32_t) kKeepAliveMaxPayloadChunkSize);
            sbuf_t        *frame_buf = keepaliveclientAllocFrameBuffer(pool, chunk_len + kKeepAliveFramePrefixSize);

            sbufSetLength(frame_buf, chunk_len);
            memoryCopyLarge(sbufGetMutablePtr(frame_buf), src, chunk_len);

            if (! keepaliveclientSendFrameNext(t, l, frame_buf, kKeepAliveFrameKindNormal, chunk_len))
            {
                bufferpoolReuseBuffer(pool, buf);
                return false;
            }

            src += chunk_len;
            remaining -= chunk_len;
        }

        bufferpoolReuseBuffer(pool, buf);
        return true;
    }

    return keepaliveclientSendFrameNext(t, l, buf, kKeepAliveFrameKindNormal, payload_len);
}

bool keepaliveclientConsumeDownstreamFrames(tunnel_t *t, line_t *l)
{
    keepaliveclient_lstate_t *ls = lineGetState(l, t);

    if (bufferstreamGetBufLen(&ls->read_stream) > kKeepAliveReadOverflowLimit)
    {
        LOGW("KeepAliveClient: downstream framed stream overflow, size=%zu limit=%u",
             bufferstreamGetBufLen(&ls->read_stream),
             (unsigned int) kKeepAliveReadOverflowLimit);
        bufferstreamEmpty(&ls->read_stream);
        return true;
    }

    while (true)
    {
        keepaliveclient_consume_result_t result = keepaliveclientConsumeOneFrame(t, l, ls);
        if (result == kKeepAliveClientConsumeNeedMore)
        {
            return true;
        }
        if (result == kKeepAliveClientConsumeLineDead)
        {
            return false;
        }
    }
}

void keepaliveclientCloseLineFromUpstream(tunnel_t *t, line_t *l)
{
    keepaliveclientUntrackLine(t, l);
    keepaliveclientLinestateDestroy(lineGetState(l, t));

    tunnelNextUpStreamFinish(t, l);
}

void keepaliveclientCloseLineFromDownstream(tunnel_t *t, line_t *l)
{
    keepaliveclientUntrackLine(t, l);
    keepaliveclientLinestateDestroy(lineGetState(l, t));

    tunnelPrevDownStreamFinish(t, l);
}
