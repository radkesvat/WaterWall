#include "structure.h"

uint64_t hpcNow(line_t *l)
{
    return wloopNowMonotonicMS(getWorkerLoop(lineGetWID(l)));
}
bool hpcAllowed(tunnel_t *t, line_t *l)
{
    hpc_tstate_t *ts = tunnelGetState(t);
    return ! ts->workers[lineGetWID(l)].quiescing && wloopNormalDispatchAllowed(getWorkerLoop(lineGetWID(l)));
}
void hpcDetachTimer(hpc_lstate_t *ls)
{
    if (! ls->timer)
        return;
    hpc_tstate_t *ts = tunnelGetState(ls->t);
    hpc_worker_t *w  = &ts->workers[lineGetWID(ls->line)];
    if (ls->timer_prev)
        ls->timer_prev->timer_next = ls->timer_next;
    else
        w->timers = ls->timer_next;
    if (ls->timer_next)
        ls->timer_next->timer_prev = ls->timer_prev;
    wtimer_t *timer = ls->timer;
    ls->timer       = NULL;
    ls->timer_prev = ls->timer_next = NULL;
    weventSetUserData(timer, NULL);
    wtimerDelete(timer);
}
void hpcDestroyState(tunnel_t *t, line_t *l)
{
    hpc_lstate_t *ls = lineGetState(l, t);
    hpcDetachTimer(ls);
    if (ls->request)
    {
        memoryZero(sbufGetMutablePtr(ls->request), sbufGetLength(ls->request));
        lineReuseBuffer(l, ls->request);
    }
    if (ls->suffix)
        lineReuseBuffer(l, ls->suffix);
    if (ls->active)
        lineReuseBuffer(l, ls->active);
    bufferbudgetReservationRelease(&ls->active_cost);
    for (unsigned d = 0; d < 2; ++d)
    {
        bufferqueueDestroy(&ls->pending[d]);
        bufferbudgetAssertEmpty(&ls->budgets[d]);
    }
    memoryFree(ls->carry);
    memoryFree(ls->saved_header);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
void hpcClose(tunnel_t *t, line_t *l)
{
    hpc_lstate_t *ls        = lineGetState(l, t);
    bool          next_init = ls->next_init;
    hpcDestroyState(t, l);
    if (next_init)
        tunnelNextUpStreamFinish(t, l);
    tunnelPrevDownStreamFinish(t, l);
}
static void timeout(wtimer_t *timer)
{
    hpc_lstate_t *ls  = weventGetUserdata(timer);
    tunnel_t     *t   = ls->t;
    line_t       *l   = ls->line;
    hpc_tstate_t *ts  = tunnelGetState(t);
    uint64_t      now = hpcNow(l);
    if ((ls->header_started && ! ls->accepted && now - ls->header_at >= ts->header_timeout) ||
        (ts->connect && ls->header_sent && ! ls->accepted && now - ls->connect_at >= ts->connect_timeout) ||
        now - ls->progress_at >= ts->idle_timeout)
    {
        hpcClose(t, l);
        return;
    }
    if (! hpcSendHeader(t, l) || ! hpcDrainUpload(t, l))
        return;
    hpcDrainResponse(t, l);
}
bool hpcStartTimer(tunnel_t *t, line_t *l)
{
    hpc_tstate_t *ts       = tunnelGetState(t);
    hpc_lstate_t *ls       = lineGetState(l, t);
    uint32_t      interval = min(1000, min(ts->header_timeout, ts->idle_timeout));
    if (ts->connect)
        interval = min(interval, ts->connect_timeout);
    ls->timer = wtimerAdd(getWorkerLoop(lineGetWID(l)), timeout, interval, INFINITE);
    if (! ls->timer)
        return false;
    hpc_worker_t *w = &ts->workers[lineGetWID(l)];
    ls->timer_next  = w->timers;
    if (w->timers)
        w->timers->timer_prev = ls;
    w->timers = ls;
    weventSetUserData(ls->timer, ls);
    return true;
}
