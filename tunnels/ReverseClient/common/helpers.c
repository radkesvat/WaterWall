#include "structure.h"

#include "loggers/network_logger.h"
#include "managers/signal_manager.h"

static void reverseclientBeginConnectMessageReceived(worker_t *worker, void *arg1, void *arg2, void *arg3)
{

    discard arg2;
    discard arg3;

    tunnel_t               *t  = (tunnel_t *) arg1;
    reverseclient_tstate_t *ts = tunnelGetState(t);

    wid_t wid = worker->wid;

    line_t *ul = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), wid);
    line_t *dl = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), wid);

    reverseclient_lstate_t *uls = lineGetState(ul, t);
    reverseclient_lstate_t *dls = lineGetState(dl, t);

    reverseclientLinestateInitialize(uls, t, ul, dl);
    reverseclientLinestateInitialize(dls, t, ul, dl);

    uls->idle_handle = idletableCreateItem(ts->starved_connections,
                                           (hash_t) (uintptr_t) (uls),
                                           uls,
                                           reverseclientOnStarvedConnectionExpire,
                                           wid,
                                           ((uint64_t) (kConnectionStarvationTimeOutSec) * 1000));

    if (! withLineLocked(ul, tunnelNextUpStreamInit, t))
    {
        // decrement in finish path for non-established lines
        // ts->threadlocal_pool[wid].connecting_cons_count -= 1;
        return;
    }

    sbuf_t *handshakebuf = bufferpoolGetLargeBuffer(lineGetBufferPool(ul));
    handshakebuf         = sbufReserveSpace(handshakebuf, ts->handshake_length);
    memoryCopy(sbufGetMutablePtr(handshakebuf), ts->handshake_bytes, ts->handshake_length);
    sbufSetLength(handshakebuf, ts->handshake_length);

    tunnelNextUpStreamPayload(t, ul, handshakebuf);
}

void reverseclientInitiateConnectOnWorker(tunnel_t *t, wid_t wid, bool delay)
{
    discard delay;

    reverseclient_tstate_t *ts = tunnelGetState(t);

    /* A disconnect observed while an orderly shutdown is already accepted is
     * terminal cleanup, not demand for a replacement idle connection. */
    if (signalmanagerGetShutdownPhase() != kProgramShutdownRunning)
    {
        return;
    }

    if (ts->threadlocal_pool[wid].unused_cons_count + ts->threadlocal_pool[wid].connecting_cons_count >=
        ts->min_unused_cons)
    {
        return;
    }
    ts->threadlocal_pool[wid].connecting_cons_count += 1;

    if (UNLIKELY(! sendWorkerMessageForceQueueWithCleanup(
            wid, (WorkerMessageCallback) reverseclientBeginConnectMessageReceived, NULL, t, NULL, NULL)))
    {
        ts->threadlocal_pool[wid].connecting_cons_count -= 1;
        if (! signalmanagerRequestShutdownPreservingAcceptedStatus(1))
        {
            abortProgramNow(1);
        }
        if (signalmanagerGetExitCode() != 0)
        {
            LOGF("ReverseClient: failed to admit required connection-start task on worker %u", (unsigned int) wid);
        }
        else
        {
            LOGD("ReverseClient: skipped replacement connection on worker %u during accepted shutdown",
                 (unsigned int) wid);
        }
    }
}

void reverseclientOnStarvedConnectionExpire(idle_item_t *idle_con)
{
    reverseclient_lstate_t *ls = idle_con->userdata;

    tunnel_t               *t  = ls->t;
    reverseclient_tstate_t *ts = tunnelGetState(t);

    if (ls->idle_handle == NULL)
    {
        LOGF("ReverseClient: onStarvedConnectionExpire called with NULL idle_handle");
        abortProgramNow(1);
        return;
    }
    ls->idle_handle = NULL;

    assert(! ls->pair_connected);

    line_t *ul = ls->u;
    line_t *dl = ls->d;

    if (lineIsEstablished(ul))
    {
        ts->threadlocal_pool[lineGetWID(ul)].unused_cons_count -= 1;
    }
    else
    {
        ts->threadlocal_pool[lineGetWID(ul)].connecting_cons_count -= 1;
    }
    LOGW("ReverseClient: a idle connection detected and closed");

    reverseclientInitiateConnectOnWorker(t, lineGetWID(ul), false);

    tunnelNextUpStreamFinish(t, ul);

    reverseclientLinestateDestroy(ls);
    reverseclientLinestateDestroy(lineGetState(dl, t));

    lineDestroy(ul);
    lineDestroy(dl);
}
