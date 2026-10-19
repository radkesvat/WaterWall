#include "structure.h"

#include "loggers/network_logger.h"

static void usercontrollerDeleteTimer(wtimer_t **timer)
{
    if (*timer == NULL)
    {
        return;
    }

    weventSetUserData(*timer, NULL);
    wtimerDelete(*timer);
    *timer = NULL;
}

void usercontrollerTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                  context;
    usercontroller_tstate_t *ts = tunnelGetState(t);
    atomicStoreExplicit(&ts->shaping_stopping, true, memory_order_release);
}

void usercontrollerTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadIsEventWorkerWID(wid));

    usercontroller_tstate_t *ts = tunnelGetState(t);
    if (ts->worker_states == NULL || wid >= ts->worker_count)
    {
        return;
    }

    usercontrollerDeleteTimer(&ts->worker_states[wid].sweep_timer);
    usercontroller_worker_state_t *ws = &ts->worker_states[wid];
    ws->quiesced                      = true;
    for (size_t i = 0; i < ws->line_count; ++i)
    {
        line_t *line = ws->lines[i];
        if (lineIsAlive(line))
            usercontrollerBandwidthQuiesce(lineGetState(line, t));
    }
}
