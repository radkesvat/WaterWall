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
    if (s->header_storage[d])
    {
        memoryZero(s->header_storage[d], s->header_length[d]);
        memoryFree(s->header_storage[d]);
        s->header_storage[d] = NULL;
    }
    s->trailer_context[d] = (hps_header_t) {0};
    s->header_length[d]   = 0;
}

size_t hpsPendingBytes(hps_session_t *s)
{
    size_t n = 0;
    for (unsigned i = 0; i < 2; ++i)
    {
        if (s->input[i])
            n += sbufGetLength(s->input[i]);
        if (s->output[i])
            n += sbufGetLength(s->output[i]);
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
        const sbuf_t *buffers[] = {s->input[i], s->output[i]};
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
    if (n > hpsSettings(s)->max_pending - hpsPendingBytes(s))
        return false;
    sbuf_t *old    = s->input[direction];
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
        hpsDiscardBuffer(s, &s->input[direction]);
        s->input[direction] = old = b;
    }
    memoryCopy(sbufGetMutablePtr(old) + length, data, n);
    sbufSetLength(old, (uint32_t) (length + n));
    return true;
}

static void hpsConsumeInput(hps_session_t *s, hps_direction_t d, size_t n)
{
    sbuf_t *b = s->input[d];
    if (n == sbufGetLength(b))
        hpsDiscardBuffer(s, &s->input[d]);
    else
        sbufShiftRight(b, (uint32_t) n);
}

bool hpsQueueOutput(hps_session_t *s, hps_direction_t d, const char *data, size_t n)
{
    assert(! s->output[d]);
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
    s->output[d] = b;
    return true;
}

/* Copy only the complete header; body and pipelined bytes stay in their FIFO. */
int hpsReadHeader(hps_session_t *s, hps_direction_t d, char **block)
{
    sbuf_t *b = s->input[d];
    if (! b)
        return 0;
    if (! s->header_at[d])
        s->header_at[d] = hpsNowMs();
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
    s->header_at[d] = 0;
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
    hps_body_t *b = d == kHpsUpstream ? &s->request_body : &s->response_body;
    if (b->kind == kHpsBodyDone)
        return kHpsStepDone;
    if (s->paused[d] || s->output[d])
        return kHpsStepBlocked;
    if (! s->input[d])
        return kHpsStepNeedInput;
    size_t used;
    bool   emit;
    int    result = hpsBodyStep(b,
                             sbufGetRawPtr(s->input[d]),
                             sbufGetLength(s->input[d]),
                             d == kHpsDownstream && s->http10,
                             &s->trailer_context[d],
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
        memoryCopy(sbufGetMutablePtr(out), sbufGetRawPtr(s->input[d]), used);
        sbufSetLength(out, (uint32_t) used);
    }
    hpsConsumeInput(s, d, used);
    s->progress_at = hpsNowMs();
    if (out)
        hpsDeliverPayload(s, d, out);
    return kHpsStepProgress;
}

/* Takes buf on every path. The callback holds the session and exact-line
 * references, and publishes its receive counter across this admission. */
void hpsAcceptPayload(hps_session_t *s, line_t *l, sbuf_t *buf, hps_direction_t d)
{
    const uint64_t allowance = kHpsDeliveryHeadroomBytes;
    if (! sbufGetLength(buf))
    {
        lineReuseBuffer(l, buf);
        return;
    }
    if (s->incoming[d])
    {
        /* The outer callback still owns older bytes. Append after them, not to
         * the deferred slot which its pump could consume ahead of that suffix.
         * Nested input shares the existing D allowance; it gets no new budget. */
        const uint64_t length = (uint64_t) sbufGetLength(s->incoming[d]) + sbufGetLength(buf);
        const uint64_t older  = s->deferred[d] ? sbufGetLength(s->deferred[d]) : 0;
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
            sbufMoveTo(merged, s->incoming[d], sbufGetLength(s->incoming[d]));
            sbufMoveTo(merged, buf, sbufGetLength(buf));
            hpsDiscardBuffer(s, &s->incoming[d]);
            lineReuseBuffer(l, buf);
            s->incoming[d] = merged;
        }
        return;
    }
    s->incoming[d]       = buf;
    const bool oversized = (uint64_t) sbufGetLength(buf) > allowance + hpsSettings(s)->max_pending;
    /* Preserve streaming of larger callbacks when their prefix can make immediate
     * progress. Only the retained remainder consumes delivery headroom. */
    while (hpsIsActive(s) && s->incoming[d] && ! oversized && sbufGetLength(s->incoming[d]) > allowance &&
           ! s->deferred[d] && ! s->paused[d] && s->phase != kHpsError &&
           ! (d == kHpsUpstream &&
              (s->upload_stopped || s->phase == kHpsConnect ||
               (s->phase == kHpsExchange && (! s->child_established || s->request_body.kind == kHpsBodyDone)))))
    {
        size_t room = hpsSettings(s)->max_pending - hpsPendingBytes(s);
        if ((d == kHpsUpstream ? s->phase == kHpsRequest : s->response_header) && room > 1024)
            room -= 1024;
        size_t n = min((size_t) sbufGetLength(s->incoming[d]), room);
        if (! n || ! hpsAppendInput(s, d, sbufGetRawPtr(s->incoming[d]), n))
            break;
        sbufShiftRight(s->incoming[d], (uint32_t) n);
        hpsPump(s);
    }
    buf            = s->incoming[d];
    s->incoming[d] = NULL;
    if (! buf)
        return; /* Reentrant close or an early final response settled it. */
    const uint64_t length = sbufGetLength(buf);
    const uint64_t older  = s->deferred[d] ? sbufGetLength(s->deferred[d]) : 0;
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
                sbufMoveTo(remainder, s->deferred[d], (uint32_t) older);
            sbufMoveTo(remainder, buf, (uint32_t) length);
            lineReuseBuffer(l, buf);
            hpsDiscardBuffer(s, &s->deferred[d]);
            s->deferred[d] = remainder;
        }
    }
    else
        lineReuseBuffer(l, buf);
}
