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
    assert(currentThreadOwnsWorker(wid));

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
            usercontrollerBandwidthQuiesce(usercontrollerGetLineState(t, line));
    }
}

void usercontrollerTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadOwnsWorker(wid));
    usercontroller_tstate_t *ts = tunnelGetState(t);
    if (ts->worker_states != NULL && wid < ts->worker_count)
    {
        tunnel_chain_t *chain = tunnelGetChain(t);
        if (chain != NULL && chain->finalized && chain->contains_packet_node)
        {
            line_t *packet = tunnelchainGetWorkerPacketLine(chain, wid);
            if (usercontrollerGetLineState(t, packet)->phase == kUserControllerOpen)
                usercontrollerLinestateDestroy(t, packet);
        }
    }
}
