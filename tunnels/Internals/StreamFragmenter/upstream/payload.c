#include "loggers/network_logger.h"
#include "structure.h"

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
    if (eligible && ! roll100(ts->bypass_chance))
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
    streamfragmenter_job_t *job = memoryAllocateZero(sizeof(*job));
    if (job == NULL || ! bufferbudgetTryReserve(&ls->budget, buf, &job->reservation))
    {
        memoryFree(job);
        lineReuseBuffer(l, buf);
        LOGW("StreamFragmenter: upstream retention refused (8 MiB / 1024 jobs); closing line");
        streamfragmenterCloseLine(t, l);
        return;
    }
    job->buf  = buf;
    job->cuts = cuts;
    if (ls->tail != NULL)
        ls->tail->next = job;
    else
        ls->head = job;
    ls->tail = job;
    if (streamfragmenterUpdatePressure(t, l))
        streamfragmenterDrain(t, l);
}
