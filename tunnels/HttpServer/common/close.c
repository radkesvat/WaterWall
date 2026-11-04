#include "structure.h"

#include "loggers/network_logger.h"

void httpserverStartCloseDrain(httpserver_lstate_t *ls)
{
    assert(ls->next_finished && ls->runtime_proto == kHttpServerRuntimeHttp2);
    if (ls->close_drain_deadline_ms != 0)
    {
        return;
    }
    const httpserver_tstate_t *ts = tunnelGetState(ls->tunnel);
    assert(ts->close_drain_timeout_ms > 0 && ts->close_drain_timeout_ms <= kHttpServerMaxCloseDrainTimeoutMs);
    ls->close_drain_deadline_ms = getHRTimeUs() / 1000 + ts->close_drain_timeout_ms;
}

bool httpserverCloseDrainAllowed(httpserver_lstate_t *ls)
{
    if (ls->close_drain_deadline_ms == 0 || getHRTimeUs() / 1000 < ls->close_drain_deadline_ms)
    {
        return true;
    }
    LOGW("HttpServer: HTTP/2 response drain timed out");
    return false;
}

static void closeDrainTimeout(wtimer_t *timer)
{
    httpserver_lstate_t *ls = weventGetUserdata(timer);
    assert(ls->close_drain_timer == timer);
    const uint64_t now = getHRTimeUs() / 1000;

    /* Dispatch owns this one-shot unless reset revives it. Published line
     * state must not retain its pointer across terminal callbacks. */
    ls->close_drain_timer = NULL;
    if (now < ls->close_drain_deadline_ms)
    {
        /* The loop can round a long timer down; preserve the original deadline. */
        if (wtimerReset(timer, (uint32_t) (ls->close_drain_deadline_ms - now)))
        {
            ls->close_drain_timer = timer;
            return;
        }
    }
    else
    {
        LOGW("HttpServer: HTTP/2 response drain timed out");
    }

    httpserverTransportClosePrevDirection(ls->tunnel, ls->line, ls);
}

bool httpserverArmCloseDrain(httpserver_lstate_t *ls)
{
    assert(ls->close_drain_deadline_ms != 0);
    const uint64_t now = getHRTimeUs() / 1000;
    if (now >= ls->close_drain_deadline_ms)
    {
        LOGW("HttpServer: HTTP/2 response drain timed out");
        return false;
    }
    if (ls->close_drain_timer != NULL)
    {
        return true;
    }

    wloop_t       *loop      = getWorkerLoop(lineGetWID(ls->line));
    const uint64_t remaining = ls->close_drain_deadline_ms - now;
    ls->close_drain_timer    = wtimerAdd(loop, closeDrainTimeout, (uint32_t) remaining, 1);
    if (ls->close_drain_timer == NULL)
    {
        return false;
    }
    weventSetUserData(ls->close_drain_timer, ls);
    return true;
}

void httpserverCancelCloseDrain(httpserver_lstate_t *ls)
{
    wtimer_t *timer             = ls->close_drain_timer;
    ls->close_drain_timer       = NULL;
    ls->close_drain_deadline_ms = 0;
    if (timer != NULL)
    {
        weventSetUserData(timer, NULL);
        wtimerDelete(timer);
    }
}
