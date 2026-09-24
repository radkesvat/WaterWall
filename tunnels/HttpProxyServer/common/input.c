#include "structure.h"

/* Shared bounded storage and HTTP framing for both Payload callbacks. */

void hpsDiscardBuffer(hps_session_t *s, sbuf_t **slot)
{
    if (*slot)
    {
        sbuf_t *b = *slot;
        *slot     = NULL;
        lineReuseBuffer(s->client, b);
    }
}

void hpsClearHeader(hps_session_t *s, hps_direction_t d)
{
    hps_direction_state_t *dir = &s->directions[d];
    if (dir->header_storage)
    {
        memoryZero(dir->header_storage, dir->header_length);
        memoryFree(dir->header_storage);
        dir->header_storage = NULL;
    }
    dir->trailer_context = (hps_header_t) {0};
    dir->header_length   = 0;
}

size_t hpsPendingBytes(hps_session_t *s)
{
    size_t n = 0;
    for (unsigned i = 0; i < 2; ++i)
    {
        const hps_direction_state_t *dir = &s->directions[i];
        if (dir->input)
            n += sbufGetLength(dir->input);
        if (dir->output)
            n += sbufGetLength(dir->output);
    }
    return n;
}

static uint64_t bufferCharge(const sbuf_t *buffer)
{
    return buffer ? (uint64_t) sbufGetTotalCapacity(buffer) + sizeof(sbuf_t) + kSbufAllocationAlignment : 0;
}

static bool remainderAllocationFits(hps_session_t *s, const sbuf_t *buffer)
{
    buffer_pool_t *pool          = lineGetBufferPool(s->client);
    const uint64_t payload_bound = max((uint64_t) bufferpoolGetSmallBufferSize(pool), 2 * kHpsDeliveryHeadroomBytes);
    const uint16_t padding       = max(bufferpoolGetMediumBufferPadding(pool),
                                 max(bufferpoolGetSmallBufferPadding(pool), bufferpoolGetLargeBufferPadding(pool)));
    uint32_t       capacity;
    return sbufTryComputeCapacity(payload_bound, padding, &capacity) &&
           bufferCharge(buffer) <= (uint64_t) capacity + sizeof(sbuf_t) + kSbufAllocationAlignment;
}

/* Four coalesced working buffers bound entries independently of TCP fragmentation. */
static bool allocationFits(hps_session_t *s, const sbuf_t *replace, const sbuf_t *candidate)
{
    uint64_t charge = bufferCharge(candidate);
    for (unsigned i = 0; i < 2; ++i)
    {
        const hps_direction_state_t *dir       = &s->directions[i];
        const sbuf_t                *buffers[] = {dir->input, dir->output};
        for (unsigned j = 0; j < 2; ++j)
            if (buffers[j] && buffers[j] != replace)
                charge += bufferCharge(buffers[j]);
    }
    return charge <= (uint64_t) hpsSettings(s)->max_pending * 4;
}

static sbuf_t *hpsMakeBuffer(hps_session_t *s, size_t n)
{
    buffer_pool_t *pool = lineGetBufferPool(s->client);
    sbuf_t        *b    = bufferpoolTryGetBestFit(pool, n, bufferpoolGetLargeBufferPadding(pool));
    if (b == NULL)
        return NULL;
    if (sbufGetMaximumWriteableSize(b) < n)
    {
        lineReuseBuffer(s->client, b);
        return NULL;
    }
    return b;
}

bool hpsAppendInput(hps_session_t *s, hps_direction_t direction, const unsigned char *data, size_t n)
{
    hps_direction_state_t *dir = &s->directions[direction];
    if (n > hpsSettings(s)->max_pending - hpsPendingBytes(s))
        return false;
    sbuf_t *old    = dir->input;
    size_t  length = old ? sbufGetLength(old) : 0;
    if (! old || sbufGetMaximumWriteableSize(old) < length + n)
    {
        sbuf_t *b = hpsMakeBuffer(s, MIN_SIZE(hpsSettings(s)->max_pending, MAX_SIZE(4096, (length + n) * 2)));
        if (! b)
            return false;
        if (! allocationFits(s, old, b))
        {
            lineReuseBuffer(s->client, b);
            return false;
        }
        if (length)
            memoryCopy(sbufGetMutablePtr(b), sbufGetRawPtr(old), length);
        hpsDiscardBuffer(s, &dir->input);
        dir->input = old = b;
    }
    memoryCopy(sbufGetMutablePtr(old) + length, data, n);
    sbufSetLength(old, (uint32_t) (length + n));
    return true;
}

static void hpsConsumeInput(hps_session_t *s, hps_direction_t d, size_t n)
{
    hps_direction_state_t *dir = &s->directions[d];
    sbuf_t                *b   = dir->input;
    if (n == sbufGetLength(b))
        hpsDiscardBuffer(s, &dir->input);
    else
        sbufShiftRight(b, (uint32_t) n);
}

bool hpsQueueOutput(hps_session_t *s, hps_direction_t d, const char *data, size_t n)
{
    hps_direction_state_t *dir = &s->directions[d];
    assert(! dir->output);
    if (n > hpsSettings(s)->max_pending - hpsPendingBytes(s))
        return false;
    sbuf_t *b = hpsMakeBuffer(s, n);
    if (! b)
        return false;
    if (! allocationFits(s, NULL, b))
    {
        lineReuseBuffer(s->client, b);
        return false;
    }
    memoryCopy(sbufGetMutablePtr(b), data, n);
    sbufSetLength(b, (uint32_t) n);
    dir->output = b;
    return true;
}

/* Copy only the complete header; body and pipelined bytes stay in their FIFO. */
int hpsReadHeader(hps_session_t *s, hps_direction_t d, char **block)
{
    hps_direction_state_t *dir = &s->directions[d];
    sbuf_t                *b   = dir->input;
    if (! b)
        return 0;
    if (! dir->header_at)
        dir->header_at = hpsNowMs(s);
    size_t               len = sbufGetLength(b), n = 0;
    const unsigned char *p = sbufGetRawPtr(b);
    for (size_t i = 0; i + 3 < len; ++i)
        if (! memoryCompare(p + i, "\r\n\r\n", 4))
        {
            n = i + 4;
            break;
        }
    if ((! n && len >= hpsSettings(s)->max_header) || n > hpsSettings(s)->max_header)
        return -431;
    size_t line = 0;
    while (line < len && p[line] != '\r' && p[line] != '\n')
        ++line;
    if (line > kHpsRequestLineLimit)
        return -414;
    if (! n)
        return 0;
    *block = memoryAllocate(n + 1);
    if (! *block)
        return -503;
    memoryCopy(*block, p, n);
    (*block)[n] = 0;
    hpsConsumeInput(s, d, n);
    dir->header_at = 0;
    return (int) n;
}

bool hpsRewriteHeaderOutput(hps_session_t *s, const hps_header_t *h, hps_direction_t d)
{
    size_t cap  = (size_t) hpsSettings(s)->max_header + 1024;
    char  *text = memoryAllocate(cap);
    if (! text)
        return false;
    size_t n = 0;
    bool   ok =
        hpsRewriteHeader(h, d == kHpsDownstream, s->http10, d == kHpsDownstream && s->close_after, text, cap, &n) &&
        hpsQueueOutput(s, d, text, n);
    memoryFree(text);
    return ok;
}

hps_step_t hpsProcessBody(hps_session_t *s, hps_direction_t d)
{
    hps_direction_state_t *dir = &s->directions[d];
    hps_body_t            *b   = &dir->body;
    if (b->kind == kHpsBodyDone)
        return kHpsStepDone;
    if (dir->paused || dir->output)
        return kHpsStepBlocked;
    if (! dir->input)
        return kHpsStepNeedInput;
    size_t used;
    bool   emit;
    int    result = hpsBodyStep(b,
                             sbufGetRawPtr(dir->input),
                             sbufGetLength(dir->input),
                             d == kHpsDownstream && s->http10,
                             &dir->trailer_context,
                             &used,
                             &emit);
    if (result < 0)
    {
        hpsFail(s, d == kHpsUpstream ? 400 : 502);
        return kHpsStepProgress;
    }
    if (! result)
        return kHpsStepNeedInput;
    if (b->kind == kHpsBodyDone)
        hpsClearHeader(s, d);
    sbuf_t *out = NULL;
    if (emit)
    {
        out = hpsMakeBuffer(s, used);
        if (! out)
        {
            hpsFail(s, 503);
            return kHpsStepProgress;
        }
        memoryCopy(sbufGetMutablePtr(out), sbufGetRawPtr(dir->input), used);
        sbufSetLength(out, (uint32_t) used);
    }
    hpsConsumeInput(s, d, used);
    s->progress_at = hpsNowMs(s);
    if (out)
        hpsDeliverPayload(s, d, out);
    return kHpsStepProgress;
}

static bool canRelaySplice(hps_session_t *s, hps_direction_t d)
{
    const hps_direction_state_t *dir = &s->directions[d];
    if ((s->phase != kHpsRelay && s->phase != kHpsFallback) || dir->paused || dir->input || dir->output ||
        dir->deferred || dir->incoming || s->pumping || s->child_initializing)
        return false;
    const hps_direction_state_t *opposite = &s->directions[d == kHpsUpstream ? kHpsDownstream : kHpsUpstream];
    if (dir->receiving != 1 || opposite->receiving != 0)
        return false;
    if (s->phase == kHpsRelay && (! s->final_committed || s->directions[kHpsDownstream].output))
        return false; /* CONNECT success must already have been handed off. */
    if (! s->child || ! s->child_entry || ! lineIsAlive(s->child))
        return false;
    return d != kHpsUpstream || ! s->upload_stopped;
}

/* Takes buf on every path. The callback holds the session and exact-line
 * references, and publishes its receive counter across this admission. */
void hpsAcceptPayload(hps_session_t *s, line_t *l, sbuf_t *buf, hps_direction_t d)
{
    hps_direction_state_t *dir = &s->directions[d];
    assert(l == (d == kHpsUpstream ? s->client : s->child));
    const uint64_t allowance = kHpsDeliveryHeadroomBytes;
    if (! sbufGetLength(buf))
    {
        lineReuseBuffer(l, buf);
        return;
    }
    if (sbufIsSplice(buf))
    {
        const uint64_t length = sbufGetLength(buf);
        if (! hpsIsActive(s) || (d == kHpsUpstream && s->upload_stopped) || s->phase == kHpsError)
        {
            lineReuseBuffer(l, buf);
            return;
        }
        if (length > allowance + hpsSettings(s)->max_pending)
        {
            lineReuseBuffer(l, buf);
            hpsFail(s, 503);
            return;
        }
        if (canRelaySplice(s, d))
        {
            s->pumping = true;
            /* Delivery consumes buf even if reentry closes either line. Nested
             * input materializes behind this dispatch; the callback pumps next. */
            hpsDeliverPayload(s, d, buf);
            s->pumping = false;
            return;
        }
        /* Every session slot is ordinary. The complete conversion is a bounded
         * temporary input (at most P+D), subject to the remainder allocation
         * bound; existing admission still decides what may survive this call. */
        sbuf_t *ordinary = hpsMakeBuffer(s, (size_t) length);
        if (! ordinary || ! remainderAllocationFits(s, ordinary))
        {
            if (ordinary)
                lineReuseBuffer(l, ordinary);
            lineReuseBuffer(l, buf);
            hpsFail(s, 503);
            return;
        }
        sbufSpliceReadToBuffer(buf, ordinary, (uint32_t) length);
        lineReuseBuffer(l, buf);
        buf = ordinary;
    }
    assert(! sbufIsSplice(buf));
    if (dir->incoming)
    {
        /* The outer callback still owns older bytes. Append after them, not to
         * the deferred slot which its pump could consume ahead of that suffix.
         * Nested input shares the existing D allowance; it gets no new budget. */
        const uint64_t length = (uint64_t) sbufGetLength(dir->incoming) + sbufGetLength(buf);
        const uint64_t older  = dir->deferred ? sbufGetLength(dir->deferred) : 0;
        sbuf_t        *merged = length + older <= allowance ? hpsMakeBuffer(s, (size_t) length) : NULL;
        if (! merged || ! remainderAllocationFits(s, merged))
        {
            if (merged)
                lineReuseBuffer(l, merged);
            lineReuseBuffer(l, buf);
            hpsFail(s, 503);
        }
        else
        {
            sbufMoveTo(merged, dir->incoming, sbufGetLength(dir->incoming));
            sbufMoveTo(merged, buf, sbufGetLength(buf));
            hpsDiscardBuffer(s, &dir->incoming);
            lineReuseBuffer(l, buf);
            dir->incoming = merged;
        }
        return;
    }
    dir->incoming        = buf;
    const bool oversized = (uint64_t) sbufGetLength(buf) > allowance + hpsSettings(s)->max_pending;
    /* Preserve streaming of larger callbacks when their prefix can make immediate
     * progress. Only the retained remainder consumes delivery headroom. */
    while (hpsIsActive(s) && dir->incoming && ! oversized && sbufGetLength(dir->incoming) > allowance &&
           ! dir->deferred && ! dir->paused && s->phase != kHpsError &&
           ! (d == kHpsUpstream &&
              (s->upload_stopped || s->phase == kHpsConnect ||
               (s->phase == kHpsExchange && (! s->child_established || dir->body.kind == kHpsBodyDone)))))
    {
        size_t room = hpsSettings(s)->max_pending - hpsPendingBytes(s);
        if ((d == kHpsUpstream ? s->phase == kHpsRequest : s->response_header) && room > 1024)
            room -= 1024;
        size_t n = min((size_t) sbufGetLength(dir->incoming), room);
        if (! n || ! hpsAppendInput(s, d, sbufGetRawPtr(dir->incoming), n))
            break;
        sbufShiftRight(dir->incoming, (uint32_t) n);
        hpsPump(s);
    }
    buf           = dir->incoming;
    dir->incoming = NULL;
    if (! buf)
        return; /* Reentrant close or an early final response settled it. */
    const uint64_t length = sbufGetLength(buf);
    const uint64_t older  = dir->deferred ? sbufGetLength(dir->deferred) : 0;
    if (! hpsIsActive(s) || (d == kHpsUpstream && s->upload_stopped) || s->phase == kHpsError)
        lineReuseBuffer(l, buf);
    else if (oversized || length + older > allowance)
    {
        lineReuseBuffer(l, buf);
        hpsFail(s, 503);
    }
    else if (length != 0)
    {
        /* Use bounded best-fit storage at admission instead of retaining an
         * arbitrarily oversized carrier allocation. Working storage is charged
         * separately; this slot is at most aligned(max(small, 2*D)) plus padding. */
        sbuf_t *remainder = hpsMakeBuffer(s, (size_t) (length + older));
        if (! remainder || ! remainderAllocationFits(s, remainder))
        {
            if (remainder)
                lineReuseBuffer(l, remainder);
            lineReuseBuffer(l, buf);
            hpsFail(s, 503);
        }
        else
        {
            if (older)
                sbufMoveTo(remainder, dir->deferred, (uint32_t) older);
            sbufMoveTo(remainder, buf, (uint32_t) length);
            lineReuseBuffer(l, buf);
            hpsDiscardBuffer(s, &dir->deferred);
            dir->deferred = remainder;
        }
    }
    else
        lineReuseBuffer(l, buf);
}
