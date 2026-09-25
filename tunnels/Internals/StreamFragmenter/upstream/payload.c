#include "loggers/network_logger.h"
#include "structure.h"

static bool commitHello(tunnel_t *t, line_t *l)
{
    streamfragmenter_lstate_t       *ls  = lineGetState(l, t);
    const streamfragmenter_tstate_t *ts  = tunnelGetState(t);
    streamfragmenter_job_t          *job = ls->candidate;
    assert(job != NULL && job->kind == kStreamFragmenterJobCandidate && job->cuts != 0);

    const uint32_t length  = streamfragmenterTlsRewriteLength(job->buf, job->cuts, ts);
    buffer_pool_t *pool    = lineGetBufferPool(l);
    const uint16_t padding = bufferpoolGetLargeBufferPadding(pool);
    uint32_t       capacity;
    if (! sbufTryComputeCapacity(length, padding, &capacity))
        return false;

    sbuf_t *replacement = bufferpoolTryGetBestFit(pool, length, padding);
    if (replacement == NULL)
        return false;
    sbufSetLength(replacement, length);
    buffer_budget_reservation_t replacement_reservation = {0};
    if (! bufferbudgetTryReserve(&ls->budget, replacement, &replacement_reservation))
    {
        lineReuseBuffer(l, replacement);
        return false;
    }
    uint32_t *mapped = memoryAllocateZero(sizeof(uint32_t) * ts->cut_count);
    if (mapped == NULL || ! streamfragmenterTlsRewrite(job->buf, job->cuts, ts, replacement, mapped))
    {
        memoryFree(mapped);
        bufferbudgetReservationRelease(&replacement_reservation);
        lineReuseBuffer(l, replacement);
        return false;
    }

    streamfragmenterCancelAssemblyTimer(ls);
    ls->protocol     = kStreamFragmenterOpaque;
    ls->candidate    = NULL;
    sbuf_t *original = job->buf;
    bufferbudgetReservationRelease(&job->reservation);
    job->buf         = replacement;
    job->reservation = replacement_reservation;
    job->mapped_cuts = mapped;
    job->kind        = kStreamFragmenterJobHello;
    lineReuseBuffer(l, original);
    return true;
}

static bool growCandidate(tunnel_t *t, line_t *l, streamfragmenter_job_t *job, uint32_t needed)
{
    assert(job != NULL && job->kind == kStreamFragmenterJobCandidate && needed <= kStreamFragmenterMaxWire);
    uint32_t target = min(sbufGetMaximumWriteableSize(job->buf), (uint32_t) kStreamFragmenterMaxWire);
    if (needed <= target)
        return true;
    while (target < needed)
        target = target > kStreamFragmenterMaxWire / 2 ? kStreamFragmenterMaxWire : target * 2;

    buffer_pool_t *pool    = lineGetBufferPool(l);
    const uint16_t padding = bufferpoolGetLargeBufferPadding(pool);
    uint32_t       capacity;
    if (! sbufTryComputeCapacity(target, padding, &capacity))
        return false;
    sbuf_t *replacement = bufferpoolTryGetBestFit(pool, target, padding);
    if (replacement == NULL)
        return false;
    const uint32_t length = sbufGetLength(job->buf);
    sbufSetLength(replacement, length);
    streamfragmenter_lstate_t  *ls                      = lineGetState(l, t);
    buffer_budget_reservation_t replacement_reservation = {0};
    if (! bufferbudgetTryReserve(&ls->budget, replacement, &replacement_reservation))
    {
        lineReuseBuffer(l, replacement);
        return false;
    }
    if (length != 0)
        memoryCopy(sbufGetMutablePtr(replacement), sbufGetRawPtr(job->buf), length);
    sbuf_t *original = job->buf;
    bufferbudgetReservationRelease(&job->reservation);
    job->buf         = replacement;
    job->reservation = replacement_reservation;
    lineReuseBuffer(l, original);
    return true;
}

/* Consume only the current parser milestone. In particular, a completing input's
 * suffix stays in its original wrapper for ordinary FIFO admission. */
static bool feedCandidate(tunnel_t *t, line_t *l, sbuf_t *input)
{
    streamfragmenter_lstate_t *ls = lineGetState(l, t);
    assert(ls->protocol == kStreamFragmenterCollecting && ls->candidate != NULL);
    streamfragmenter_job_t *job = ls->candidate;
    while (sbufGetLength(input) != 0)
    {
        if (getHRTimeUs() >= ls->assembly_deadline_us)
        {
            streamfragmenterCandidateFallback(t, l);
            break;
        }
        const uint32_t count = min(streamfragmenterTlsNeed(&ls->tls_parser), sbufGetLength(input));
        assert(count > 0);
        const uint32_t old_length = sbufGetLength(job->buf);
        if (count > kStreamFragmenterMaxWire - old_length)
        {
            streamfragmenterCandidateFallback(t, l);
            break;
        }
        if (! growCandidate(t, l, job, old_length + count))
            return false;
        if (! bufferbudgetTryAcquire(&ls->budget, (buffer_budget_cost_t) {count, 0, 0}))
            return false;
        job->reservation.cost.bytes += count;
        uint8_t *destination = sbufGetMutablePtr(job->buf) + old_length;
        sbufReadRangeToMemory(input, destination, count);
        sbufSetLength(job->buf, old_length + count);
        const streamfragmenter_tls_result_t result = streamfragmenterTlsFeed(&ls->tls_parser, destination, count);
        if (result == kStreamFragmenterTlsHeaderReady)
        {
            const streamfragmenter_tstate_t *ts = tunnelGetState(t);
            for (uint8_t i = 0; i < ts->cut_count && ts->cuts[i].offset < ls->tls_parser.handshake_total; ++i)
                if (roll100(ts->cuts[i].chance))
                    job->cuts |= UINT64_C(1) << i;
            if (job->cuts == 0)
            {
                streamfragmenterCandidateFallback(t, l);
                break;
            }
        }
        else if (result == kStreamFragmenterTlsComplete)
        {
            if (getHRTimeUs() >= ls->assembly_deadline_us)
                streamfragmenterCandidateFallback(t, l);
            else if (! commitHello(t, l))
                return false;
            break;
        }
        else if (result == kStreamFragmenterTlsPassUnchanged)
        {
            streamfragmenterCandidateFallback(t, l);
            break;
        }
    }
    if (ls->protocol == kStreamFragmenterCollecting && getHRTimeUs() >= ls->assembly_deadline_us)
        streamfragmenterCandidateFallback(t, l);
    return true;
}

static bool startCandidate(tunnel_t *t, line_t *l, uint64_t now)
{
    streamfragmenter_lstate_t       *ls      = lineGetState(l, t);
    const streamfragmenter_tstate_t *ts      = tunnelGetState(t);
    buffer_pool_t                   *pool    = lineGetBufferPool(l);
    const uint16_t                   padding = bufferpoolGetLargeBufferPadding(pool);
    uint32_t                         capacity;
    if (! sbufTryComputeCapacity(4096, padding, &capacity))
        return false;
    sbuf_t *accumulator = bufferpoolTryGetBestFit(pool, 4096, padding);
    if (accumulator == NULL)
        return false;
    if (! streamfragmenterEnqueue(t, l, accumulator, 0, kStreamFragmenterJobCandidate))
    {
        lineReuseBuffer(l, accumulator);
        return false;
    }
    ls->candidate            = ls->tail;
    ls->protocol             = kStreamFragmenterCollecting;
    ls->tls_parser           = (streamfragmenter_tls_parser_t) {0};
    const uint64_t duration  = (uint64_t) ts->tls_hello_timeout_ms * 1000;
    ls->assembly_deadline_us = now > UINT64_MAX - duration ? UINT64_MAX : now + duration;
    return true;
}

void streamfragmenterTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    streamfragmenter_lstate_t       *ls       = lineGetState(l, t);
    const streamfragmenter_tstate_t *ts       = tunnelGetState(t);
    bool                             eligible = ! ls->exhausted;
    if (eligible)
    {
        if (ts->timed)
        {
            ls->exhausted = (! ts->wait_for_est || ls->est_received) && getHRTimeUs() >= ls->deadline_us;
            eligible      = ! ls->exhausted;
        }
        else
            ls->exhausted = --ls->remaining == 0;
    }

    uint64_t cuts = 0;
    if (ts->tls_hello_fragment)
    {
        if (ls->protocol == kStreamFragmenterCollecting && sbufGetLength(buf) == 0)
        {
            lineReuseBuffer(l, buf);
            if (getHRTimeUs() >= ls->assembly_deadline_us)
            {
                streamfragmenterCandidateFallback(t, l);
                streamfragmenterDrain(t, l);
            }
            return;
        }
        if (ls->protocol == kStreamFragmenterAwaitingData && sbufGetLength(buf) != 0)
        {
            if (! eligible || roll100(ts->bypass_chance))
                ls->protocol = kStreamFragmenterOpaque;
            else if (! startCandidate(t, l, getHRTimeUs()))
            {
                lineReuseBuffer(l, buf);
                LOGW("StreamFragmenter: TLS candidate retention refused; closing line");
                streamfragmenterCloseLine(t, l);
                return;
            }
        }
        if (ls->protocol == kStreamFragmenterCollecting)
        {
            if (! feedCandidate(t, l, buf))
            {
                lineReuseBuffer(l, buf);
                LOGW("StreamFragmenter: TLS candidate conversion refused; closing line");
                streamfragmenterCloseLine(t, l);
                return;
            }
            if (ls->protocol == kStreamFragmenterCollecting && ! streamfragmenterArmAssemblyTimer(t, l))
            {
                lineReuseBuffer(l, buf);
                LOGW("StreamFragmenter: assembly timer admission refused; closing line");
                streamfragmenterCloseLine(t, l);
                return;
            }
            if (sbufGetLength(buf) == 0)
                lineReuseBuffer(l, buf);
            else if (! streamfragmenterEnqueue(t, l, buf, 0, kStreamFragmenterJobOrdinary))
            {
                lineReuseBuffer(l, buf);
                LOGW("StreamFragmenter: TLS suffix retention refused; closing line");
                streamfragmenterCloseLine(t, l);
                return;
            }
            streamfragmenterDrain(t, l);
            return;
        }
    }
    else if (eligible && ! roll100(ts->bypass_chance))
    {
        for (uint8_t i = 0; i < ts->cut_count && ts->cuts[i].offset < sbufGetLength(buf); ++i)
            if (roll100(ts->cuts[i].chance))
                cuts |= UINT64_C(1) << i;
    }

    if (cuts == 0 && ls->head == NULL && ! ls->draining && ! ls->consumer_paused && ! ls->waiting_for_est)
    {
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }
    if (! streamfragmenterEnqueue(t, l, buf, cuts, kStreamFragmenterJobOrdinary))
    {
        lineReuseBuffer(l, buf);
        LOGW("StreamFragmenter: upstream retention refused (8 MiB / 1024 jobs); closing line");
        streamfragmenterCloseLine(t, l);
        return;
    }
    streamfragmenterDrain(t, l);
}
