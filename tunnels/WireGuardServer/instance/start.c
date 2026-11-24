#include "WireGuardServer/structure.h"

void wireguardserverTick(wtimer_t *timer)
{
    server_t *state = weventGetUserdata(timer);
    if (! atomicLoad(&state->dispatch.open))
        return;
    wireguardserverRetryOrphanCloses(state);
    wireguardserverReconcile(state, true);
    wireguardCommonLoop(&state->engine);
    wireguardserverServicePending(state);
}

static void packetInit(void *worker, void *arg1, void *arg2, void *arg3)
{
    discard   arg2;
    discard   arg3;
    tunnel_t *t     = arg1;
    server_t *state = tunnelGetState(t);
    if (! atomicLoad(&state->dispatch.open))
        return;
    line_t *line = tunnelchainGetWorkerPacketLine(t->chain, ((worker_t *) worker)->wid);
    tunnelNextUpStreamInit(t, line);
}

void wireguardserverTunnelOnStart(tunnel_t *t)
{
    server_t *state = tunnelGetState(t);
    /* Each routed server initializes its own consumers on the shared worker packet lines. */
    for (wid_t wid = 0; wid < t->chain->workers_count; ++wid)
    {
        const worker_message_submit_result_e result =
            sendWorkerMessageForceQueueWithCleanup(wid, packetInit, NULL, t, NULL, NULL);
        if (result != kWorkerMessageSubmitAccepted)
        {
            startupFailureRecord(1);
            return;
        }
    }
    state->timer = wtimerAdd(getWorkerLoop(0), wireguardserverTick, WIREGUARDIF_TIMER_MSECS, INFINITE);
    if (state->timer == NULL)
    {
        startupFailureRecord(1);
        return;
    }
    weventSetUserData(state->timer, state);
}
