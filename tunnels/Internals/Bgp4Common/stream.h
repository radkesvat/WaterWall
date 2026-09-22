#pragma once

#include "loggers/network_logger.h"
#include "splice_stream.h"
#include "wwapi.h"

/* The BGP-like wire and logical retention policy do not depend on pool geometry. */
enum
{
    kBgpFramePrefix    = 19,
    kBgpMaxApplication = 65534,
    kBgpMaxWireFrame   = 65553,
    kBgpPendingBytes   = 2 * 1024 * 1024 + kBgpMaxWireFrame,
    kBgpOutputEntries  = 1024
};

typedef struct bgp_permission_s
{
    bool paused;
    bool pumping;
    bool producer_paused;
    bool notifying;
} bgp_permission_t;

typedef struct bgp_stream_s
{
    splice_stream_t *read_stream;
    buffer_queue_t   output;
    bgp_permission_t encode;
    bgp_permission_t decode;
    bool             client;
    bool             open; // Client OPEN admitted, or server OPEN validated.
} bgp_stream_t;

static inline bool bgpStreamInitialize(bgp_stream_t *s, line_t *l, bool client)
{
    *s = (bgp_stream_t) {.client = client};
    bufferqueueInitEmpty(&s->output);
    s->read_stream = splicestreamCreate(lineGetBufferPool(l), kBgpFramePrefix);
    return s->read_stream != NULL;
}

static inline void bgpStreamDestroy(bgp_stream_t *s)
{
    splicestreamDestroy(s->read_stream);
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
    const uint8_t *h = splicestreamPeekHeader(s->read_stream);
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
 * complete frames retained during Pause are governed by the independent budget. */
static inline sbuf_t *bgpReadFrame(tunnel_t *t, line_t *l, bgp_stream_t *s, bool *valid)
{
    *valid           = bgpHeaderValid(s);
    const uint8_t *h = splicestreamPeekHeader(s->read_stream);
    if (! *valid || h == NULL)
        return NULL;
    const uint32_t bytes = (((uint32_t) h[16] << 8) | h[17]) - 1;
    if (splicestreamBodyBytes(s->read_stream) < bytes)
        return NULL;
    buffer_pool_t *pool = lineGetBufferPool(l);
    sbuf_t        *dest = tunnelGetChain(t)->supports_splice ? bufferpoolGetSpliceBuffer(pool) : NULL;
    sbuf_t        *body = splicestreamMoveFrame(s->read_stream, dest, bytes);
    if (! s->client && ! s->open)
    {
        uint8_t open[10];
        sbufReadRangeToMemory(body, open, sizeof(open));
        if (open[0] != 4 || sbufGetLength(body) <= open[9])
        {
            bufferpoolReuseBuffer(pool, body);
            *valid = false;
            return NULL;
        }
        uint8_t optional[255];
        sbufReadRangeToMemory(body, optional, open[9]);
        s->open = true;
    }
    return body;
}

/* A notification can re-enter either direction or finish this borrowed line.
 * A reference protects storage; the stream becomes NULL on local Finish even
 * if the creator has not yet marked the borrowed line dead. */
static inline bool bgpNotify(tunnel_t *t, line_t *l, bgp_stream_t *s, bool encode, bool pause)
{
    bgp_permission_t *g = encode ? &s->encode : &s->decode;
    g->producer_paused  = pause;
    g->notifying        = true;
    const bool upstream = encode == s->client;
    lineRef(l);
    if (upstream)
    {
        if (pause)
            tunnelPrevDownStreamPause(t, l);
        else
            tunnelPrevDownStreamResume(t, l);
    }
    else
    {
        if (pause)
            tunnelNextUpStreamPause(t, l);
        else
            tunnelNextUpStreamResume(t, l);
    }
    const bool alive = lineIsAlive(l) && s->read_stream != NULL;
    if (alive)
        g->notifying = false;
    lineUnref(l);
    return alive;
}

static inline void bgpPump(tunnel_t *t, line_t *l, bgp_stream_t *s, bool encode)
{
    bgp_permission_t *g = encode ? &s->encode : &s->decode;
    if (g->pumping || g->notifying)
        return;
    g->pumping          = true;
    const bool upstream = encode == s->client;
    lineRef(l);
    for (;;)
    {
        while (! g->paused)
        {
            sbuf_t *buf;
            if (encode)
                buf = bufferqueuePopFront(&s->output);
            else
            {
                bool valid;
                buf = bgpReadFrame(t, l, s, &valid);
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
            if (! lineIsAlive(l) || s->read_stream == NULL)
                goto done;
        }
        if (g->paused == g->producer_paused)
            break;
        /* An incomplete receive frame needs producer Resume to make progress. */
        if (! bgpNotify(t, l, s, encode, g->paused))
            goto done;
    }
    g->pumping = false;
done:
    lineUnref(l);
}

static inline void bgpPermission(tunnel_t *t, line_t *l, bgp_stream_t *s, bool encode, bool pause)
{
    bgp_permission_t *g = encode ? &s->encode : &s->decode;
    g->paused           = pause;
    /* Pause takes effect immediately, including inside an outward Payload.
     * Resume waits for the active pump to finish its older work. */
    if (pause && ! g->producer_paused && ! g->notifying && ! bgpNotify(t, l, s, encode, true))
        return;
    bgpPump(t, l, s, encode);
}

static inline void bgpDecode(tunnel_t *t, line_t *l, bgp_stream_t *s, sbuf_t *buf)
{
    if (sbufGetLength(buf) > kBgpPendingBytes - splicestreamLength(s->read_stream))
    {
        lineReuseBuffer(l, buf);
        bgpClose(t, l, s, "receive byte limit exceeded");
        return;
    }
    if (! splicestreamPush(s->read_stream, buf))
    {
        bgpClose(t, l, s, "receive queue allocation failed");
        return;
    }
    if (! bgpHeaderValid(s))
    {
        bgpClose(t, l, s, "invalid marker, length or message type");
        return;
    }
    bgpPump(t, l, s, false);
}

static inline void bgpPrepend(sbuf_t *buf, const uint8_t *open, uint32_t open_length)
{
    const uint32_t application = sbufGetLength(buf);
    assert(sbufGetLeftCapacity(buf) >= kBgpFramePrefix + open_length);
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
    const size_t   queued     = bufferqueueGetBufCount(&s->output);
    const bool     direct =
        frames == 1 && queued == 0 && ! s->encode.paused && ! s->encode.pumping && ! s->encode.notifying;
    if (wire_bytes > kBgpPendingBytes - bufferqueueGetBufLen(&s->output) ||
        (! direct && (frames > kBgpOutputEntries - queued || ! bufferqueueReserveExtra(&s->output, (size_t) frames))))
    {
        bufferpoolReuseBuffer(pool, input);
        bgpClose(t, l, s, "encoded byte/entry limit or queue reservation failed");
        return;
    }
    if (direct)
    {
        bgpPrepend(input, open, open_length);
        if (s->client)
            s->open = true;
        s->encode.pumping = true;
        lineRef(l);
        if (s->client)
            tunnelNextUpStreamPayload(t, l, input);
        else
            tunnelPrevDownStreamPayload(t, l, input);
        if (lineIsAlive(l) && s->read_stream != NULL)
        {
            s->encode.pumping = false;
            bgpPump(t, l, s, true);
        }
        lineUnref(l);
        return;
    }
    /* Reservation and byte/entry admission precede consumption. No callbacks
     * observe this batch until all its independently owned frames are queued. */
    for (uint64_t i = 0; i < frames; ++i)
    {
        const uint32_t count = min(sbufGetLength(input), i == 0 ? first : (uint32_t) kBgpMaxApplication);
        sbuf_t        *frame;
        if (count == sbufGetLength(input) && sbufGetLeftCapacity(input) >= kBgpFramePrefix + open_length)
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
        discard bufferqueuePushBack(&s->output, frame);
        open_length = 0;
    }
    if (input != NULL)
        bufferpoolReuseBuffer(pool, input);
    if (s->client)
        s->open = true;
    bgpPump(t, l, s, true);
}
