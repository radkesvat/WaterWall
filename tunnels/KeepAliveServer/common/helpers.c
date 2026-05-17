#include "structure.h"

#include "loggers/network_logger.h"

typedef enum keepaliveserver_consume_result_e
{
    kKeepAliveServerConsumeNeedMore = 0,
    kKeepAliveServerConsumeContinue,
    kKeepAliveServerConsumeLineDead
} keepaliveserver_consume_result_t;

static bool keepaliveserverIsPacketLine(tunnel_t *t, line_t *l)
{
    tunnel_chain_t *chain = tunnelGetChain(t);
    if (chain == NULL || chain->packet_lines == NULL)
    {
        return false;
    }

    return tunnelchainGetWorkerPacketLine(chain, lineGetWID(l)) == l;
}

static sbuf_t *keepaliveserverAllocFrameBuffer(buffer_pool_t *pool, uint32_t frame_len)
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

static bool keepaliveserverSendFramePrev(tunnel_t *t, line_t *l, sbuf_t *buf, uint8_t frame_kind, uint32_t payload_len)
{
    const uint32_t frame_body_len = payload_len + kKeepAliveServerFrameTypeSize;
    const uint32_t frame_len      = frame_body_len + kKeepAliveServerFrameLengthSize;

    if (keepaliveserverIsPacketLine(t, l) && frame_len > kMaxAllowedPacketLength)
    {
        LOGE("KeepAliveServer: worker packet line payload exceeds kMaxAllowedPacketLength after framing: %u > %u",
             (unsigned int) frame_len, (unsigned int) kMaxAllowedPacketLength);
        lineReuseBuffer(l, buf);
        return true;
    }

    if (sbufGetLeftCapacity(buf) < kKeepAliveServerFramePrefixSize)
    {
        LOGW("KeepAliveServer: dropping frame because left padding is smaller than required header size");
        lineReuseBuffer(l, buf);
        return true;
    }

    if (sbufGetMaximumWriteableSize(buf) < frame_body_len)
    {
        buf = sbufReserveSpace(buf, frame_body_len);
    }

    sbufShiftLeft(buf, kKeepAliveServerFramePrefixSize);

    uint8_t *frame = sbufGetMutablePtr(buf);
    uint16_t frame_body_len_network = htons((uint16_t) frame_body_len);
    sbufByteCopy(frame, &frame_body_len_network, (uint32_t) sizeof(frame_body_len_network));
    frame[kKeepAliveServerFrameLengthSize] = frame_kind;

    sbufSetLength(buf, frame_len);
    return withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, buf);
}

static bool keepaliveserverSendControlFrame(tunnel_t *t, line_t *l, uint8_t frame_kind)
{
    if (! lineIsAlive(l))
    {
        return true;
    }

    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(l));
    sbufSetLength(buf, 0);
    return keepaliveserverSendFramePrev(t, l, buf, frame_kind, 0);
}

static keepaliveserver_consume_result_t keepaliveserverConsumeOneFrame(tunnel_t *t, line_t *l,
                                                                       keepaliveserver_lstate_t *ls)
{
    if (bufferstreamGetBufLen(&ls->read_stream) < kKeepAliveServerFramePrefixSize)
    {
        return kKeepAliveServerConsumeNeedMore;
    }

    uint8_t header[kKeepAliveServerFrameLengthSize];
    bufferstreamViewBytesAt(&ls->read_stream, 0, header, sizeof(header));

    uint16_t frame_body_len_network;
    sbufByteCopy(&frame_body_len_network, header, (uint32_t) sizeof(frame_body_len_network));
    uint16_t frame_body_len = ntohs(frame_body_len_network);

    if (frame_body_len < kKeepAliveServerFrameTypeSize)
    {
        LOGW("KeepAliveServer: invalid upstream keepalive frame length: %u", (unsigned int) frame_body_len);
        bufferstreamEmpty(&ls->read_stream);
        return kKeepAliveServerConsumeNeedMore;
    }

    if ((uint32_t) frame_body_len + kKeepAliveServerFrameLengthSize > (uint32_t) bufferstreamGetBufLen(&ls->read_stream))
    {
        return kKeepAliveServerConsumeNeedMore;
    }

    sbuf_t *frame = bufferstreamReadExact(&ls->read_stream, kKeepAliveServerFrameLengthSize + frame_body_len);
    sbufShiftRight(frame, kKeepAliveServerFrameLengthSize);

    const uint8_t  frame_kind  = sbufReadUI8(frame);
    const uint32_t payload_len = frame_body_len - kKeepAliveServerFrameTypeSize;

    switch (frame_kind)
    {
    case kKeepAliveServerFrameKindNormal:
        if (payload_len == 0)
        {
            LOGW("KeepAliveServer: dropping empty normal frame");
            lineReuseBuffer(l, frame);
            return kKeepAliveServerConsumeContinue;
        }

        sbufShiftRight(frame, kKeepAliveServerFrameTypeSize);
        if (! withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, frame))
        {
            return kKeepAliveServerConsumeLineDead;
        }
        return kKeepAliveServerConsumeContinue;

    case kKeepAliveServerFrameKindPing:
        lineReuseBuffer(l, frame);
        if (! keepaliveserverSendControlFrame(t, l, kKeepAliveServerFrameKindPong))
        {
            return kKeepAliveServerConsumeLineDead;
        }
        return kKeepAliveServerConsumeContinue;

    case kKeepAliveServerFrameKindPong:
        lineReuseBuffer(l, frame);
        return kKeepAliveServerConsumeContinue;

    default:
        LOGW("KeepAliveServer: dropping unknown frame kind %u", (unsigned int) frame_kind);
        lineReuseBuffer(l, frame);
        return kKeepAliveServerConsumeContinue;
    }
}

bool keepaliveserverSendNormalFrameDownstream(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    const uint32_t payload_len = sbufGetLength(buf);

    if (payload_len == 0)
    {
        lineReuseBuffer(l, buf);
        return true;
    }

    if (keepaliveserverIsPacketLine(t, l) && payload_len + kKeepAliveServerFramePrefixSize > kMaxAllowedPacketLength)
    {
        LOGE("KeepAliveServer: worker packet line payload exceeds kMaxAllowedPacketLength after framing: %u > %u",
             (unsigned int) (payload_len + kKeepAliveServerFramePrefixSize), (unsigned int) kMaxAllowedPacketLength);
        lineReuseBuffer(l, buf);
        return true;
    }

    if (payload_len > kKeepAliveServerMaxPayloadChunkSize)
    {
        buffer_pool_t *pool      = lineGetBufferPool(l);
        const uint8_t *src       = sbufGetRawPtr(buf);
        uint32_t       remaining = payload_len;

        while (remaining > 0)
        {
            const uint32_t chunk_len = min(remaining, (uint32_t) kKeepAliveServerMaxPayloadChunkSize);
            sbuf_t        *frame_buf = keepaliveserverAllocFrameBuffer(pool, chunk_len + kKeepAliveServerFramePrefixSize);

            sbufSetLength(frame_buf, chunk_len);
            memoryCopyLarge(sbufGetMutablePtr(frame_buf), src, chunk_len);

            if (! keepaliveserverSendFramePrev(t, l, frame_buf, kKeepAliveServerFrameKindNormal, chunk_len))
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

    return keepaliveserverSendFramePrev(t, l, buf, kKeepAliveServerFrameKindNormal, payload_len);
}

bool keepaliveserverConsumeUpstreamFrames(tunnel_t *t, line_t *l)
{
    keepaliveserver_lstate_t *ls = lineGetState(l, t);

    if (bufferstreamGetBufLen(&ls->read_stream) > kKeepAliveServerReadOverflowLimit)
    {
        LOGW("KeepAliveServer: upstream framed stream overflow, size=%zu limit=%u",
             bufferstreamGetBufLen(&ls->read_stream), (unsigned int) kKeepAliveServerReadOverflowLimit);
        bufferstreamEmpty(&ls->read_stream);
        return true;
    }

    while (true)
    {
        keepaliveserver_consume_result_t result = keepaliveserverConsumeOneFrame(t, l, ls);
        if (result == kKeepAliveServerConsumeNeedMore)
        {
            return true;
        }
        if (result == kKeepAliveServerConsumeLineDead)
        {
            return false;
        }
    }
}

void keepaliveserverCloseLineFromUpstream(tunnel_t *t, line_t *l)
{
    lineLock(l);
    keepaliveserverLinestateDestroy(lineGetState(l, t));

    tunnelNextUpStreamFinish(t, l);

    lineUnlock(l);
}

void keepaliveserverCloseLineFromDownstream(tunnel_t *t, line_t *l)
{
    lineLock(l);
    keepaliveserverLinestateDestroy(lineGetState(l, t));

    tunnelPrevDownStreamFinish(t, l);

    lineUnlock(l);
}
