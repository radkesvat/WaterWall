#include "structure.h"

static void timeout(wtimer_t *timer)
{
    hps_session_t *s = weventGetUserdata(timer);
    hpsRetain(s);
    const hps_direction_state_t *up    = &s->directions[kHpsUpstream];
    const hps_direction_state_t *down  = &s->directions[kHpsDownstream];
    uint64_t now   = hpsNowMs(s);
    unsigned error = 0;
    if (up->header_at && now - up->header_at >= hpsSettings(s)->header_timeout)
        error = 408;
    else if (down->header_at && now - down->header_at >= hpsSettings(s)->header_timeout)
        error = 504;
    else if (s->connect_at && now - s->connect_at >= hpsSettings(s)->connect_timeout)
        error = 504;
    else if (now - s->progress_at >= hpsSettings(s)->idle_timeout)
    {
        if (s->phase == kHpsRequest && ! up->input)
            hpsClose(s, false);
        else
            error = 504;
    }
    if (error)
    {
        hpsFail(s, error);
        hpsPump(s);
    }
    hpsRelease(s);
}

void httpproxyserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    hps_tstate_t *ts = tunnelGetState(t);
    hps_lstate_t *ls = lineGetState(l, t);
    *ls              = (hps_lstate_t) {.line = l};
    hps_session_t *s = memoryAllocateZero(sizeof(*s));
    if (! s || ts->workers[lineGetWID(l)].quiescing)
    {
        memoryFree(s);
        hpsClearLineState(l, t);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }
    s->t           = t;
    s->client      = l;
    s->references  = 1;
    s->progress_at = hpsNowMs(s);
    lineRef(l);
    ls->session = s;
    hpsRetain(s);
    uint32_t interval = min(1000, min(ts->header_timeout, min(ts->connect_timeout, ts->idle_timeout)));
    s->timer          = wtimerAdd(getWorkerLoop(lineGetWID(l)), timeout, interval, INFINITE);
    if (! s->timer)
        hpsClose(s, false);
    else
    {
        hps_worker_t *w = &ts->workers[lineGetWID(l)];
        s->timer_next   = w->timers;
        if (s->timer_next)
            s->timer_next->timer_prev = s;
        w->timers = s;
        weventSetUserData(s->timer, s);
    }
    hpsRelease(s);
}
