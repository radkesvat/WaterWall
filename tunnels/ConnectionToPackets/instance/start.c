#include "structure.h"

#include "loggers/network_logger.h"

static void ctpQueueWorkerPacketInitCleanup(void *arg1, void *arg2, void *arg3)
{
    discard arg2;
    discard arg3;
    tunnelasyncsessionUnref(arg1);
}

void ctpQueueWorkerPacketInit(void *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg2;
    discard arg3;

    tunnel_async_session_t *session = arg1;
    tunnel_t               *t       = NULL;

    if (! tunnelasyncsessionEnter(session, &t))
    {
        tunnelasyncsessionUnref(session);
        return;
    }

    /*
     * Start queues one of these per worker, and a worker may not reach its copy
     * until after onStop() has already run on another. Initializing the packet
     * side toward a next node whose stop hook has completed is a lifecycle
     * violation, so a late message is simply dropped.
     */
    if (UNLIKELY(! ctpNextGateEnter(t)))
    {
        tunnelasyncsessionLeave(session);
        tunnelasyncsessionUnref(session);
        return;
    }

    line_t *l = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), getCurrentEventWorkerWID());

    if (UNLIKELY(! withLineLocked(l, tunnelNextUpStreamInit, t)))
    {
        /* Release non-line lifetime references before the Category-D abort. */
        ctpNextGateLeave(t);
        tunnelasyncsessionLeave(session);
        tunnelasyncsessionUnref(session);
        LOGF("ConnectionToPackets: worker packet line died during packet-side init");
        abortProgramNow(1);
        return;
    }
    ctpNextGateLeave(t);
    tunnelasyncsessionLeave(session);
    tunnelasyncsessionUnref(session);
}

void ctpTunnelOnStart(tunnel_t *t)
{
    ctp_tstate_t *ts = tunnelGetState(t);

    if (UNLIKELY(! deviceLifetimeGateOpen(&ts->prev_gate) || ! deviceLifetimeGateOpen(&ts->next_gate) ||
                 ! deviceLifetimeGateOpen(&ts->packet_ingress_gate) || ! tunnelasyncsessionOpen(ts->async_session)))
    {
        LOGF("ConnectionToPackets: failed to open callback admission gates");
        abortProgramNow(1);
    }

    /*
     * A chain that starts with a layer-4 adapter never receives the node
     * manager's layer-3 head initialization, so the packet side would otherwise
     * never see Init. Queue it per worker instead of re-entering packet-side init
     * paths inline during node-manager startup.
     */
    for (wid_t wi = 0; wi < getWorkersCount(); wi++)
    {
        tunnelasyncsessionRef(ts->async_session);
        if (! sendWorkerMessageForceQueueWithCleanup(
                wi, ctpQueueWorkerPacketInit, ctpQueueWorkerPacketInitCleanup, ts->async_session, NULL, NULL))
        {
            LOGF("ConnectionToPackets: required packet-line Init was refused on worker %u", (unsigned int) wi);
            abortProgramNow(1);
        }
    }
}
