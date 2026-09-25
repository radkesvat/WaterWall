#include "structure.h"

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
