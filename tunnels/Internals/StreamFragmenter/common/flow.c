#include "loggers/network_logger.h"
#include "structure.h"

static void fragmentTimer(wtimer_t *timer);

bool streamfragmenterUpdatePressure(tunnel_t *t, line_t *l)
{
    streamfragmenter_lstate_t *ls    = lineGetState(l, t);
    const buffer_budget_cost_t usage = bufferbudgetGetUsage(&ls->budget);
    if (usage.charge >= kStreamFragmenterHighCharge || usage.entries >= kStreamFragmenterHighJobs)
        ls->locally_paused = true;
    else if (usage.charge <= kStreamFragmenterLowCharge && usage.entries <= kStreamFragmenterLowJobs)
        ls->locally_paused = false;
    const bool paused = ls->consumer_paused || ls->locally_paused;
    if (paused == ls->source_paused)
        return true;
    ls->source_paused = paused;
    if (! lineCallWithRef(l, paused ? tunnelPrevDownStreamPause : tunnelPrevDownStreamResume, t))
        return false;
    return ((streamfragmenter_lstate_t *) lineGetState(l, t))->tunnel == t;
}

bool streamfragmenterEnqueue(tunnel_t *t, line_t *l, sbuf_t *buf, uint64_t cuts, streamfragmenter_job_kind_t kind)
{
    streamfragmenter_lstate_t *ls  = lineGetState(l, t);
    streamfragmenter_job_t    *job = memoryAllocateZero(sizeof(*job));
    if (job == NULL)
        return false;
    if (! bufferbudgetTryReserve(&ls->budget, buf, &job->reservation))
    {
        memoryFree(job);
        return false;
    }
    job->buf  = buf;
    job->cuts = cuts;
    job->kind = kind;
    if (ls->tail != NULL)
        ls->tail->next = job;
    else
        ls->head = job;
    ls->tail = job;
    return true;
}

void streamfragmenterCancelAssemblyTimer(streamfragmenter_lstate_t *ls)
{
    if (ls->timer_kind != kStreamFragmenterTimerAssembly)
        return;
    assert(ls->timer != NULL);
    weventSetUserData(ls->timer, NULL);
    wtimerDelete(ls->timer);
    ls->timer      = NULL;
    ls->timer_kind = kStreamFragmenterTimerNone;
}

void streamfragmenterCandidateFallback(tunnel_t *t, line_t *l)
{
    streamfragmenter_lstate_t *ls = lineGetState(l, t);
    assert(ls->protocol == kStreamFragmenterCollecting && ls->candidate != NULL);
    streamfragmenterCancelAssemblyTimer(ls);
    ls->candidate->kind = kStreamFragmenterJobOrdinary;
    ls->candidate->cuts = 0;
    ls->candidate       = NULL;
    ls->protocol        = kStreamFragmenterOpaque;
}

bool streamfragmenterArmAssemblyTimer(tunnel_t *t, line_t *l)
{
    streamfragmenter_lstate_t *ls = lineGetState(l, t);
    assert(ls->protocol == kStreamFragmenterCollecting && ls->candidate != NULL);
    if (ls->timer_kind == kStreamFragmenterTimerAssembly)
        return true;
    assert(ls->timer == NULL && ls->timer_kind == kStreamFragmenterTimerNone);
    const uint64_t now = getHRTimeUs();
    if (now >= ls->assembly_deadline_us)
    {
        streamfragmenterCandidateFallback(t, l);
        return true;
    }
    const uint64_t remaining = ls->assembly_deadline_us - now;
    const uint32_t delay     = (uint32_t) ((remaining + 999) / 1000);
    ls->timer                = wtimerAdd(getWorkerLoop(lineGetWID(l)), fragmentTimer, delay, 1);
    if (ls->timer == NULL)
        return false;
    ls->timer_kind = kStreamFragmenterTimerAssembly;
    weventSetUserData(ls->timer, ls);
    return true;
}

static void fragmentTimer(wtimer_t *timer)
{
    streamfragmenter_lstate_t *ls = weventGetUserdata(timer);
    assert(ls != NULL && ls->timer == timer);
    const streamfragmenter_timer_kind_t kind = ls->timer_kind;
    ls->timer                                = NULL; /* The event loop reclaims this one-shot after dispatch. */
    ls->timer_kind                           = kStreamFragmenterTimerNone;
    if (kind == kStreamFragmenterTimerAssembly)
    {
        if (getHRTimeUs() < ls->assembly_deadline_us)
        {
            if (! streamfragmenterArmAssemblyTimer(ls->tunnel, ls->line))
            {
                LOGW("StreamFragmenter: assembly timer admission refused; closing line");
                streamfragmenterCloseLine(ls->tunnel, ls->line);
            }
            return;
        }
        streamfragmenterCandidateFallback(ls->tunnel, ls->line);
    }
    else
        assert(kind == kStreamFragmenterTimerDelay);
    streamfragmenterDrain(ls->tunnel, ls->line);
}

void streamfragmenterDrain(tunnel_t *t, line_t *l)
{
    streamfragmenter_lstate_t *ls = lineGetState(l, t);
    if (ls->draining)
        return;
    ls->draining = true;
    lineRef(l);
    const streamfragmenter_tstate_t *ts = tunnelGetState(t);
    for (;;)
    {
        if (ls->protocol == kStreamFragmenterCollecting && getHRTimeUs() >= ls->assembly_deadline_us)
            streamfragmenterCandidateFallback(t, l);
        if (! streamfragmenterUpdatePressure(t, l))
            break;
        /* Pressure callbacks can append work or destroy the complete FIFO. */
        if (ls->protocol == kStreamFragmenterCollecting && getHRTimeUs() >= ls->assembly_deadline_us)
            streamfragmenterCandidateFallback(t, l);
        streamfragmenter_job_t *job = ls->head;
        if (job == NULL || ls->timer_kind == kStreamFragmenterTimerDelay || ls->waiting_for_est ||
            job->kind == kStreamFragmenterJobCandidate)
            break;
        while (job->next_cut < ts->cut_count && ! (job->cuts & (UINT64_C(1) << job->next_cut)))
            ++job->next_cut;
        const bool     cut = job->next_cut < ts->cut_count;
        const uint64_t now = getHRTimeUs();
        if (! job->delay_started)
        {
            const uint64_t delay = cut ? (uint64_t) ts->cuts[job->next_cut].delay_ms * 1000 : 0;
            job->due_us          = now > UINT64_MAX - delay ? UINT64_MAX : now + delay;
            job->delay_started   = true;
        }
        if (now < job->due_us)
        {
            const uint32_t delay = (uint32_t) ((job->due_us - now + 999) / 1000);
            ls->timer            = wtimerAdd(getWorkerLoop(lineGetWID(l)), fragmentTimer, delay, 1);
            if (ls->timer == NULL)
            {
                LOGW("StreamFragmenter: timer admission refused; closing line");
                streamfragmenterCloseLine(t, l);
            }
            else
            {
                ls->timer_kind = kStreamFragmenterTimerDelay;
                weventSetUserData(ls->timer, ls);
            }
            break;
        }
        /* Timers keep elapsed time during Pause. Due work waits here for Resume.
         * Rechecking the deadline also handles the timer API's coarse rounding. */
        if (ls->consumer_paused)
            break;

        sbuf_t *output;
        if (cut)
        {
            const uint32_t offset = job->kind == kStreamFragmenterJobHello ? job->mapped_cuts[job->next_cut]
                                                                           : ts->cuts[job->next_cut].offset;
            const uint32_t length = offset - job->consumed;
            buffer_pool_t *pool   = lineGetBufferPool(l);
            uint32_t       capacity;
            const uint16_t padding = bufferpoolGetLargeBufferPadding(pool);
            if (! sbufTryComputeCapacity(length, padding, &capacity))
            {
                LOGW("StreamFragmenter: fragment allocation geometry refused; closing line");
                streamfragmenterCloseLine(t, l);
                break;
            }
            output = sbufIsSplice(job->buf) ? bufferpoolGetSpliceBuffer(pool) : NULL;
            output = sbufMoveRangeTo(pool, job->buf, output, length, length, padding);
            job->consumed += length;
            ++job->next_cut;
            job->delay_started = false;
            buffer_budget_cost_t cost;
            const bool           valid = bufferbudgetTryGetCost(job->buf, &cost);
            assert(valid);
            discard valid;
            bufferbudgetReservationReduce(&job->reservation, cost);
        }
        else
        {
            output   = job->buf;
            ls->head = job->next;
            if (ls->head == NULL)
                ls->tail = NULL;
            bufferbudgetReservationRelease(&job->reservation);
            memoryFree(job->mapped_cuts);
            memoryFree(job);
        }
        /* Publish remainder ownership and accounting before the handoff. Nested
         * arrivals append behind it; Finish can release it synchronously. */
        if (! lineCallWithRefWithBuf(l, tunnelNextUpStreamPayload, t, output) || ls->tunnel != t)
            break;
    }
    if (lineIsAlive(l) && ls->tunnel == t)
        ls->draining = false;
    lineUnref(l);
}
