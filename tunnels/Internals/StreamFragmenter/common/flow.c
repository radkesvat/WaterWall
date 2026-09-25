#include "loggers/network_logger.h"
#include "structure.h"

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

static void fragmentTimer(wtimer_t *timer)
{
    streamfragmenter_lstate_t *ls = weventGetUserdata(timer);
    assert(ls != NULL && ls->timer == timer);
    ls->timer = NULL; /* The event loop reclaims this one-shot after dispatch. */
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
        if (! streamfragmenterUpdatePressure(t, l))
            break;
        /* Pressure callbacks can append work or destroy the complete FIFO. */
        streamfragmenter_job_t *job = ls->head;
        if (job == NULL || ls->timer != NULL)
            break;
        while (job->next_cut < ts->cut_count && ! (job->cuts & (UINT64_C(1) << job->next_cut)))
            ++job->next_cut;
        const bool     cut = job->next_cut < ts->cut_count;
        const uint64_t now = getHRTimeUs();
        if (! job->delay_started)
        {
            job->due_us        = now + (cut ? (uint64_t) ts->cuts[job->next_cut].delay_ms * 1000 : 0);
            job->delay_started = true;
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
                weventSetUserData(ls->timer, ls);
            break;
        }
        /* Timers keep elapsed time during Pause. Due work waits here for Resume.
         * Rechecking the deadline also handles the timer API's coarse rounding. */
        if (ls->consumer_paused)
            break;

        sbuf_t *output;
        if (cut)
        {
            const uint32_t length = ts->cuts[job->next_cut].offset - job->consumed;
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
