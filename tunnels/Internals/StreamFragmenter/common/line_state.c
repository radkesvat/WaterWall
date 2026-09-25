#include "structure.h"

void streamfragmenterLinestateInitialize(streamfragmenter_lstate_t *ls, tunnel_t *t, line_t *l)
{
    assert(ls != NULL && t != NULL && l != NULL);
    const streamfragmenter_tstate_t *ts                 = tunnelGetState(t);
    const bool                       shaping_enabled    = ts->scope != 0 && ts->cut_count != 0;
    const bool                       start_timed_window = ts->timed && ! ts->wait_for_est;

    *ls           = (streamfragmenter_lstate_t) {0};
    ls->tunnel    = t;
    ls->line      = l;
    ls->remaining = ts->scope;

    ls->deadline_us = start_timed_window ? getHRTimeUs() + (uint64_t) ts->scope * 1000 : 0;
    ls->exhausted   = ! shaping_enabled;
    ls->protocol = shaping_enabled && ts->tls_hello_fragment ? kStreamFragmenterAwaitingData : kStreamFragmenterOpaque;
    ls->waiting_for_est = ts->wait_for_est;
    bufferbudgetInit(
        &ls->budget,
        (buffer_budget_cost_t) {kStreamFragmenterHardCharge, kStreamFragmenterHardCharge, kStreamFragmenterHardJobs});
}

void streamfragmenterLinestateDestroy(streamfragmenter_lstate_t *ls)
{
    if (ls->timer != NULL)
    {
        weventSetUserData(ls->timer, NULL);
        wtimerDelete(ls->timer);
        ls->timer = NULL;
    }
    while (ls->head != NULL)
    {
        streamfragmenter_job_t *job = ls->head;
        ls->head                    = job->next;
        lineReuseBuffer(ls->line, job->buf);
        bufferbudgetReservationRelease(&job->reservation);
        memoryFree(job->mapped_cuts);
        memoryFree(job);
    }
    bufferbudgetAssertEmpty(&ls->budget);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}

void streamfragmenterCloseLine(tunnel_t *t, line_t *l)
{
    streamfragmenterLinestateDestroy(lineGetState(l, t));
    /* Ordinary left-owned stream: close the borrowing side before its creator. */
    tunnelNextUpStreamFinish(t, l);
    tunnelPrevDownStreamFinish(t, l);
}
