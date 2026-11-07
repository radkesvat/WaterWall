#pragma once

#include "loggers/network_logger.h"
#include "wwapi.h"

/* The BGP-like wire and retention limits do not depend on pool geometry. */
enum
{
    kBgpFramePrefix     = 19,
    kBgpMaxApplication  = 65534,
    kBgpMaxWireFrame    = 65553,
    kBgpPendingBytes    = 2 * 1024 * 1024 + kBgpMaxWireFrame,
    kBgpReadChargeLimit = 2 * kBgpPendingBytes,
    kBgpOutputChargeLimit = 8U * 1024U * 1024U
};

typedef struct bgp_stream_s
{
    splice_frame_reader_t reader;
    buffer_queue_t        output;
    uint8_t               open_optional_remaining;
    bool                  encode_pumping : 1;
    bool                  client : 1;
    bool                  open : 1; // Client OPEN admitted, or server OPEN validated.
} bgp_stream_t;

static inline void bgpStreamInitialize(bgp_stream_t *s, line_t *l, bool client, bool splice_output)
{
    *s = (bgp_stream_t) {.client = client};
    bufferqueueInitEmpty(&s->output);
    spliceframereaderInit(
        &s->reader, lineGetBufferPool(l), kBgpFramePrefix, kBgpPendingBytes, kBgpReadChargeLimit, splice_output);
}

static inline void bgpStreamDestroy(bgp_stream_t *s)
{
    spliceframereaderDestroy(&s->reader);
    bufferqueueDestroy(&s->output);
    memoryZeroAligned32(s, tunnelGetCorrectAlignedLineStateSize(sizeof(*s)));
}

static inline void bgpClose(tunnel_t *t, line_t *l, bgp_stream_t *s, const char *reason)
{
    LOGE("Bgp4: %s", reason);
    bgpStreamDestroy(s);
    lineRef(l);
    tunnelNextUpStreamFinish(t, l);
    if (lineIsAlive(l))
        tunnelPrevDownStreamFinish(t, l);
    lineUnref(l);
}

/* The header cache is borrowed only until extraction mutates the stream. */
static inline bool bgpHeaderValid(const bgp_stream_t *s)
{
    /* The active header was validated before BeginFrame. In particular, the
     * initial OPEN stays cached while its application bytes stream onward. */
    if (spliceframereaderFrameActive(&s->reader))
        return true;
    const uint8_t *h = spliceframereaderPeekHeader(&s->reader);
    if (h == NULL)
        return true;
    for (unsigned i = 0; i < 16; ++i)
        if (h[i] != 0xff)
            return false;
    const uint32_t length = ((uint32_t) h[16] << 8) | h[17];
    if (length <= 1)
        return false;
    if (! s->client && ! s->open)
        return h[18] == 1 && length > 11;
    return h[18] >= 2 && h[18] <= 5;
}

/* A valid incomplete frame is necessarily smaller than kBgpMaxWireFrame;
 * input retained during reentry shares the independent receive budget. */
static inline sbuf_t *bgpReadChunk(line_t *l, bgp_stream_t *s, bool *valid)
{
    *valid = bgpHeaderValid(s);
    if (! *valid)
        return NULL;
    if (! spliceframereaderFrameActive(&s->reader))
    {
        const uint8_t *h = spliceframereaderPeekHeader(&s->reader);
        if (h == NULL)
            return NULL;
        const uint32_t bytes      = (((uint32_t) h[16] << 8) | h[17]) - 1;
        const bool     first_open = ! s->client && ! s->open;
        if (first_open && ! spliceframereaderBodyReady(&s->reader, 10))
            return NULL;
        spliceframereaderBeginFrame(&s->reader, bytes);
        if (first_open)
        {
            uint8_t open[10];
            sbuf_t *prefix = spliceframereaderTakeChunk(&s->reader, sizeof(open));
            sbufReadRangeToMemory(prefix, open, sizeof(open));
            lineReuseBuffer(l, prefix);
            if (open[0] != 4 || spliceframereaderFrameRemaining(&s->reader) <= open[9])
            {
                *valid = false;
                return NULL;
            }
            s->open_optional_remaining = open[9];
        }
    }
    if (! s->client && ! s->open)
    {
        const uint32_t skip = min((uint32_t) s->open_optional_remaining, spliceframereaderFrameAvailable(&s->reader));
        if (skip != 0)
        {
            spliceframereaderDiscardChunk(&s->reader, skip);
            s->open_optional_remaining -= skip;
        }
        if (s->open_optional_remaining != 0)
            return NULL;
        s->open = true;
    }
    const uint32_t bytes = spliceframereaderFrameAvailable(&s->reader);
    return bytes == 0 ? NULL : spliceframereaderTakeChunk(&s->reader, bytes);
}

/* Deliver available application chunks through advisory Pause. Nested input joins
 * the FIFO; the active pump owns delivery until more wire bytes are needed. A reference
 * protects storage, while the attached reader detects retired borrowed-line state.
 * Decode entry belongs to the caller that received kSpliceFrameDrain. */
static inline void bgpPump(tunnel_t *t, line_t *l, bgp_stream_t *s, bool encode)
{
    if (encode)
    {
        if (s->encode_pumping)
            return;
        s->encode_pumping = true;
    }
    const bool upstream = encode == s->client;
    lineRef(l);
    for (;;)
    {
        sbuf_t *buf;
        if (encode)
            buf = bufferqueuePopFront(&s->output);
        else
        {
            bool valid;
            buf = bgpReadChunk(l, s, &valid);
            if (! valid)
            {
                bgpClose(t, l, s, "invalid marker, length, type or OPEN fields");
                goto done;
            }
        }
        if (buf == NULL)
            break;
        /* Pop/extract settles our bytes before transferring ownership. */
        if (upstream)
            tunnelNextUpStreamPayload(t, l, buf);
        else
            tunnelPrevDownStreamPayload(t, l, buf);
        if (! lineIsAlive(l) || ! spliceframereaderIsAttached(&s->reader))
            goto done;
    }
    if (encode)
        s->encode_pumping = false;
    else
    {
        assert(spliceframereaderLength(&s->reader) < kBgpMaxWireFrame);
        if (! spliceframereaderEndDrain(&s->reader))
            bgpClose(t, l, s, "incomplete frame storage limit exceeded");
    }
done:
    lineUnref(l);
}

static inline void bgpDecode(tunnel_t *t, line_t *l, bgp_stream_t *s, sbuf_t *buf)
{
    const splice_frame_admit_t result = spliceframereaderAdmit(&s->reader, buf);
    switch (result)
    {
    case kSpliceFrameByteLimit:
        bgpClose(t, l, s, "receive byte limit exceeded");
        return;
    case kSpliceFrameChargeLimit:
        bgpClose(t, l, s, "receive storage limit exceeded");
        return;
    case kSpliceFramePushFailed:
        bgpClose(t, l, s, "receive queue capacity exceeded");
        return;
    case kSpliceFrameDrain:
    case kSpliceFrameQueued:
    case kSpliceFrameEmpty:
        break;
    }
    /* Even nested or empty input must reject an already-cached malformed head
     * before returning to the callback that submitted it. */
    if (! bgpHeaderValid(s))
    {
        bgpClose(t, l, s, "invalid marker, length or message type");
        return;
    }
    if (result == kSpliceFrameDrain)
        bgpPump(t, l, s, false);
}

static inline void bgpPrepend(sbuf_t *buf, const uint8_t *open, uint32_t open_length)
{
    const uint32_t application = sbufGetLength(buf);
    assert(sbufGetHeadroom(buf) >= kBgpFramePrefix + open_length);
    sbufShiftLeft(buf, kBgpFramePrefix + open_length);
    uint8_t *h = sbufGetMutablePtr(buf);
    memorySet(h, 0xff, 16);
    const uint32_t length = application + open_length + 1;
    assert(length <= UINT16_MAX);
    h[16] = (uint8_t) (length >> 8);
    h[17] = (uint8_t) length;
    h[18] = open_length ? 1 : (uint8_t) (2 + fastRand() % 4);
    if (open_length)
        memoryCopy(h + kBgpFramePrefix, open, open_length);
}

static inline void bgpEncode(tunnel_t *t, line_t *l, bgp_stream_t *s, sbuf_t *input, uint16_t as_number,
                             uint32_t router_id)
{
    const uint32_t length = sbufGetLength(input);
    buffer_pool_t *pool   = lineGetBufferPool(l);
    if (length == 0)
    {
        bufferpoolReuseBuffer(pool, input);
        return;
    }
    uint8_t  open[20]    = {0};
    uint32_t open_length = 0;
    if (s->client && ! s->open)
    {
        const uint8_t optional = (uint8_t) (3 + fastRand() % 8);
        open_length            = 10 + optional;
        open[0]                = 4;
        const uint16_t as_wire = htons(as_number), hold = htons(90);
        const uint32_t router_wire = htonl(router_id);
        sbufByteCopy(open + 1, &as_wire, 2);
        sbufByteCopy(open + 3, &hold, 2);
        sbufByteCopy(open + 5, &router_wire, 4);
        open[9] = optional;
        for (uint32_t i = 10; i < open_length; ++i)
            open[i] = (uint8_t) (fastRand() % 200);
    }
    const uint32_t first      = kBgpMaxApplication - open_length;
    const uint64_t remainder  = length > first ? (uint64_t) length - first : 0;
    const uint64_t frames     = 1 + (remainder + kBgpMaxApplication - 1) / kBgpMaxApplication;
    const uint64_t wire_bytes = (uint64_t) length + frames * kBgpFramePrefix + open_length;
    const size_t   queued     = bufferqueueGetEntryCount(&s->output);
    const bool     direct     = frames == 1 && queued == 0 && ! s->encode_pumping;
    if (wire_bytes > kBgpPendingBytes - bufferqueueGetLength(&s->output))
    {
        bufferpoolReuseBuffer(pool, input);
        bgpClose(t, l, s, "encoded byte limit exceeded");
        return;
    }
    if (direct)
    {
        bgpPrepend(input, open, open_length);
        if (s->client)
            s->open = true;
        s->encode_pumping = true;
        lineRef(l);
        if (s->client)
            tunnelNextUpStreamPayload(t, l, input);
        else
            tunnelPrevDownStreamPayload(t, l, input);
        if (lineIsAlive(l) && spliceframereaderIsAttached(&s->reader))
        {
            s->encode_pumping = false;
            bgpPump(t, l, s, true);
        }
        lineUnref(l);
        return;
    }
    // The finite output charge bounds existing storage; wire bytes bound this batch.
    const bool reserved = bufferqueueReserveExtra(&s->output, (size_t) frames);
    assert(reserved);
    discard reserved;

    /* Reservation and logical-byte admission precede consumption. No callbacks
     * observe this batch until all its independently owned frames are queued. */
    for (uint64_t i = 0; i < frames; ++i)
    {
        const uint32_t count = min(sbufGetLength(input), i == 0 ? first : (uint32_t) kBgpMaxApplication);
        sbuf_t        *frame;
        if (count == sbufGetLength(input) && sbufGetHeadroom(input) >= kBgpFramePrefix + open_length)
        {
            frame = input;
            input = NULL;
        }
        else
        {
            frame = sbufIsSplice(input) ? bufferpoolGetSpliceBuffer(pool) : NULL;
            frame = sbufMoveRangeTo(pool, input, frame, count, count, bufferpoolGetLargeBufferPadding(pool));
        }
        bgpPrepend(frame, open, open_length);
        const size_t charge = bufferqueueGetCharge(&s->output);
        if (charge > kBgpOutputChargeLimit || sbufGetQueueCharge(frame) > kBgpOutputChargeLimit - charge ||
            ! bufferqueueTryPushBack(&s->output, &frame))
        {
            bufferpoolReuseBuffer(pool, frame);
            if (input != NULL)
                bufferpoolReuseBuffer(pool, input);
            bgpClose(t, l, s, "encoded charge limit exceeded");
            return;
        }
        open_length = 0;
    }
    if (input != NULL)
        bufferpoolReuseBuffer(pool, input);
    if (s->client)
        s->open = true;
    bgpPump(t, l, s, true);
}
