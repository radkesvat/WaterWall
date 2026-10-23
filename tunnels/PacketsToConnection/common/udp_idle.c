#include "structure.h"

#include "loggers/network_logger.h"

static void ptcUdpIdleTimerCallback(wtimer_t *timer)
{
    ptc_lstate_t *ls = weventGetUserdata(timer);
    assert(ls != NULL && ls->udp_idle_timer == timer);

    line_t   *l = ls->line;
    tunnel_t *t = ls->tunnel;
    assert(l != NULL && t != NULL && lineIsAlive(l));

    ls->udp_idle_timer = NULL;

    if (ptcNextGateEnter(t))
    {
        ptcCloseLineFromNetwork(t, l);
        ptcNextGateLeave(t);
    }
    else
    {
        ptcCloseLineForStop(t, l);
    }
    lineUnref(l);
}

bool ptcArmUdpIdleOnOwnerThread(ptc_lstate_t *ls)
{
    if (ls->kind != kPtcLineKindUdp)
    {
        return true;
    }

    ptc_tstate_t *ts = tunnelGetState(ls->tunnel);
    if (ls->udp_idle_timer != NULL)
    {
        wtimerReset(ls->udp_idle_timer, ts->udp_idle_timeout_ms);
        return true;
    }

    ls->udp_idle_timer = wtimerAdd(getCurrentWorkerLoop(), ptcUdpIdleTimerCallback, ts->udp_idle_timeout_ms, 1);
    if (ls->udp_idle_timer == NULL)
    {
        return false;
    }
    weventSetUserData(ls->udp_idle_timer, ls);
    lineRef(ls->line);
    return true;
}

void ptcCancelUdpIdleTimer(ptc_lstate_t *ls)
{
    if (ls->udp_idle_timer == NULL)
    {
        return;
    }
    weventSetUserData(ls->udp_idle_timer, NULL);
    wtimerDelete(ls->udp_idle_timer);
    ls->udp_idle_timer = NULL;
    lineUnref(ls->line);
}
