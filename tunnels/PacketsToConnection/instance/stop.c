#include "structure.h"

#include "loggers/network_logger.h"

static void ptcConfigDrainComplete(ptc_tstate_t *state)
{
    const w_atomic_uint_value_t previous = atomicSubExplicit(&state->config_drain_remaining, 1, memory_order_release);
    assert(previous > 0);
    discard previous;
}

static void ptcDrainOwnedLinesMessage(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard arg2;
    discard arg3;

    tunnel_t     *t     = arg1;
    ptc_tstate_t *state = tunnelGetState(t);

    ptcDrainOwnedLinesOnCurrentWorker(t, worker->wid);
    ptcConfigDrainComplete(state);
}

static void ptcDrainOwnedLinesMessageCleanup(void *arg1, void *arg2, void *arg3)
{
    discard arg2;
    discard arg3;

    tunnel_t *t = arg1;
    ptcConfigDrainComplete(tunnelGetState(t));
}

static void ptcDrainOwnedLinesForConfigStop(tunnel_t *t)
{
    ptc_tstate_t *state               = tunnelGetState(t);
    uint32_t      queued_worker_count = 0;

    for (wid_t wid = 0; wid < state->owned_worker_count; ++wid)
    {
        if (! currentThreadIsEventWorkerWID(wid))
        {
            ++queued_worker_count;
        }
    }

    atomicStoreExplicit(&state->config_drain_remaining, queued_worker_count, memory_order_release);

    for (wid_t wid = 0; wid < state->owned_worker_count; ++wid)
    {
        if (currentThreadIsEventWorkerWID(wid))
        {
            ptcDrainOwnedLinesOnCurrentWorker(t, wid);
            continue;
        }

        if (UNLIKELY(! sendWorkerMessageForceQueueWithCleanup(wid,
                                                              (WorkerMessageCallback) ptcDrainOwnedLinesMessage,
                                                              ptcDrainOwnedLinesMessageCleanup,
                                                              t,
                                                              NULL,
                                                              NULL)))
        {
            LOGF("PacketsToConnection: failed to queue owned-line drain on worker %u", (unsigned int) wid);
            abortProgramNow(1);
        }
    }

    while (atomicLoadExplicit(&state->config_drain_remaining, memory_order_acquire) != 0)
    {
        deviceLifetimeYieldThread(NULL);
    }
}

void ptcTunnelOnStop(tunnel_t *t)
{
    /* Direct stop callers get the same ordering as the node-manager pre-pass. */
    ptcTunnelOnPreStop(t);

    // Process-level lwIP shutdown follows node Stop, so detach this tunnel's
    // netifs and PCBs while the core lock and tunnel state are still valid.
    ptcDestroyLwipResources(t);

    /*
     * During process shutdown worker-message admission is already closed, and
     * each worker drains its own registry from onWorkerStop(). A configuration
     * stop leaves the workers running, so synchronously marshal destruction to
     * every owning worker before the tunnel can be destroyed.
     */
    if (! isApplicationTerminating())
    {
        ptcDrainOwnedLinesForConfigStop(t);
    }
}

void ptcTunnelOnWorkerStop(tunnel_t *t, wid_t wid)
{
    assert(currentThreadIsEventWorkerWID(wid));
    ptcDrainOwnedLinesOnCurrentWorker(t, wid);
}
