#include "structure.h"

#include "loggers/network_logger.h"

static void ctpQueueWorkerPacketInitCleanup(void *arg1, void *arg2, void *arg3, worker_message_cancel_reason_e reason)
{
    discard reason;
    discard arg1;
    discard arg2;
    discard arg3;
}

static void ctpRollbackStart(ctp_tstate_t *ts)
{
    atomicStoreRelaxed(&ts->stopping, true);
    quiescenceGateCloseAndQuiesce(&ts->prev_gate, quiescenceGateYieldThread, NULL);
    quiescenceGateCloseAndQuiesce(&ts->next_gate, quiescenceGateYieldThread, NULL);
    quiescenceGateCloseAndQuiesce(&ts->packet_ingress_gate, quiescenceGateYieldThread, NULL);
}

void ctpQueueWorkerPacketInit(void *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg2;
    discard arg3;

    tunnel_t *t = arg1;

    /*
     * Start queues one of these per worker, and a worker may not reach its copy
     * until after onQuiesceRequest() has already run on another. Initializing the packet
     * side toward a next node whose stop hook has completed is a lifecycle
     * violation, so a late message is simply dropped.
     */
    if (UNLIKELY(! ctpNextGateEnter(t)))
    {
        return;
    }

    line_t *l = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), getCurrentEventWorkerWID());

    if (UNLIKELY(! withLineLocked(l, tunnelNextUpStreamInit, t)))
    {
        /* Release non-line lifetime references before the Category-D abort. */
        ctpNextGateLeave(t);
        LOGF("ConnectionToPackets: worker packet line died during packet-side init");
        abortProgramNow(1);
        return;
    }
    ctpNextGateLeave(t);
}

void ctpTunnelOnStart(tunnel_t *t)
{
    ctp_tstate_t *ts = tunnelGetState(t);

    if (UNLIKELY(! quiescenceGateOpen(&ts->prev_gate) || ! quiescenceGateOpen(&ts->next_gate) ||
                 ! quiescenceGateOpen(&ts->packet_ingress_gate)))
    {
        LOGF("ConnectionToPackets: failed to open callback admission gates");
        ctpRollbackStart(ts);
        startupFailureRecord(1);
        return;
    }

    /*
     * A chain that starts with a layer-4 adapter never receives the node
     * manager's layer-3 head initialization, so the packet side would otherwise
     * never see Init. Queue it per worker instead of re-entering packet-side init
     * paths inline during node-manager startup.
     */
    for (wid_t wi = 0; wi < getWorkersCount(); wi++)
    {
        if (sendWorkerMessageForceQueueWithCleanup(
                wi, ctpQueueWorkerPacketInit, ctpQueueWorkerPacketInitCleanup, t, NULL, NULL) !=
            kWorkerMessageSubmitAccepted)
        {
            LOGF("ConnectionToPackets: required packet-line Init was refused on worker %u", (unsigned int) wi);
            ctpRollbackStart(ts);
            startupFailureRecord(1);
            return;
        }
    }
}
