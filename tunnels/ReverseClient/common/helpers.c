#include "structure.h"

#include "loggers/network_logger.h"
#include "managers/signal_manager.h"

static reverseclient_thread_box_t *reverseclientPairBox(reverseclient_pair_t *pair)
{
    reverseclient_tstate_t *ts = tunnelGetState(pair->t);
    return &ts->threadlocal_pool[lineGetWID(pair->u)];
}

static void reverseclientRegisterPair(reverseclient_pair_t *pair)
{
    reverseclient_thread_box_t *box = reverseclientPairBox(pair);
    assert(! pair->registered);

    pair->prev = NULL;
    pair->next = box->owned_pairs;
    if (pair->next != NULL)
    {
        pair->next->prev = pair;
    }
    box->owned_pairs = pair;
    pair->registered = true;
}

static void reverseclientUnregisterPair(reverseclient_pair_t *pair)
{
    reverseclient_thread_box_t *box = reverseclientPairBox(pair);
    assert(pair->registered);

    if (pair->prev != NULL)
    {
        pair->prev->next = pair->next;
    }
    else
    {
        assert(box->owned_pairs == pair);
        box->owned_pairs = pair->next;
    }
    if (pair->next != NULL)
    {
        pair->next->prev = pair->prev;
    }
    pair->next       = NULL;
    pair->prev       = NULL;
    pair->registered = false;
}

size_t reverseclientOwnedPairCount(tunnel_t *t, wid_t wid)
{
    reverseclient_tstate_t *ts    = tunnelGetState(t);
    size_t                  count = 0;
    for (reverseclient_pair_t *pair = ts->threadlocal_pool[wid].owned_pairs; pair != NULL; pair = pair->next)
    {
        count++;
    }
    return count;
}

static void reverseclientReleasePairCounter(reverseclient_pair_t *pair)
{
    reverseclient_tstate_t     *ts  = tunnelGetState(pair->t);
    reverseclient_thread_box_t *box = reverseclientPairBox(pair);

    switch (pair->phase)
    {
    case kReverseClientPairConnecting:
        assert(box->connecting_cons_count > 0);
        box->connecting_cons_count--;
        break;
    case kReverseClientPairUnused:
        assert(box->unused_cons_count > 0);
        box->unused_cons_count--;
        break;
    case kReverseClientPairActive:
        atomicDecRelaxed(&ts->reverse_cons);
        break;
    }
}

void reverseclientClosePair(reverseclient_pair_t *pair, reverseclient_close_origin_e origin)
{
    if (pair == NULL || pair->closing)
    {
        return;
    }

    tunnel_t               *t                 = pair->t;
    reverseclient_tstate_t *ts                = tunnelGetState(t);
    line_t                 *ul                = pair->u;
    line_t                 *dl                = pair->d;
    const wid_t             wid               = lineGetWID(ul);
    const bool              finish_upstream   = pair->upstream_init_sent && origin != kReverseClientCloseFromNext;
    const bool              finish_downstream = pair->downstream_init_sent && origin != kReverseClientCloseFromPrev;

    pair->closing = true;
    reverseclientUnregisterPair(pair);

    if (pair->idle_handle != NULL)
    {
        pair->idle_handle = NULL;
        if (origin != kReverseClientCloseIdleExpiry &&
            ! idletableRemoveIdleItemByHash(wid, ts->starved_connections, (hash_t) (uintptr_t) pair))
        {
            LOGF("ReverseClient: failed to detach an owned pair from the idle table");
            abortProgramNow(1);
        }
    }

    reverseclientReleasePairCounter(pair);
    reverseclientLinestateDestroy(lineGetState(ul, t));
    reverseclientLinestateDestroy(lineGetState(dl, t));

    if (finish_upstream)
    {
        tunnelNextUpStreamFinish(t, ul);
    }
    if (finish_downstream)
    {
        tunnelPrevDownStreamFinish(t, dl);
    }

    if (lineIsAlive(ul))
    {
        lineDestroy(ul);
    }
    if (lineIsAlive(dl))
    {
        lineDestroy(dl);
    }

    memoryFree(pair);
    if (! atomicLoadRelaxed(&ts->stopping))
    {
        reverseclientInitiateConnectOnWorker(t, wid, false);
    }
}

static void reverseclientBeginConnectMessageCleanup(void *arg1, void *arg2, void *arg3,
                                                    worker_message_cancel_reason_e reason)
{
    discard arg3;
    discard reason;

    tunnel_t               *t   = arg1;
    reverseclient_tstate_t *ts  = tunnelGetState(t);
    const wid_t             wid = (wid_t) (uintptr_t) arg2;
    if (workerWIDIsEventWorker(wid) && ts->threadlocal_pool[wid].connecting_cons_count > 0)
    {
        ts->threadlocal_pool[wid].connecting_cons_count--;
    }
}

static void reverseclientBeginConnectMessageReceived(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    discard arg2;
    discard arg3;

    tunnel_t               *t   = arg1;
    reverseclient_tstate_t *ts  = tunnelGetState(t);
    const wid_t             wid = worker->wid;

    reverseclient_pair_t *pair = memoryAllocateZero(sizeof(*pair));
    if (UNLIKELY(pair == NULL))
    {
        assert(ts->threadlocal_pool[wid].connecting_cons_count > 0);
        ts->threadlocal_pool[wid].connecting_cons_count--;
        if (! signalmanagerRequestShutdownPreservingAcceptedStatus(1))
        {
            abortProgramNow(1);
        }
        return;
    }

    line_t *ul = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), wid);
    line_t *dl = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), wid);

    *pair = (reverseclient_pair_t) {.t = t, .u = ul, .d = dl, .phase = kReverseClientPairConnecting};
    reverseclientLinestateInitialize(lineGetState(ul, t), pair);
    reverseclientLinestateInitialize(lineGetState(dl, t), pair);
    reverseclientRegisterPair(pair);

    pair->idle_handle = idletableCreateItem(ts->starved_connections,
                                            (hash_t) (uintptr_t) pair,
                                            pair,
                                            reverseclientOnStarvedConnectionExpire,
                                            wid,
                                            (uint64_t) kConnectionStarvationTimeOutSec * 1000U);
    if (UNLIKELY(pair->idle_handle == NULL))
    {
        atomicStoreRelaxed(&ts->stopping, true);
        reverseclientClosePair(pair, kReverseClientCloseInternal);
        if (! signalmanagerRequestShutdownPreservingAcceptedStatus(1))
        {
            abortProgramNow(1);
        }
        return;
    }

    pair->upstream_init_sent = true;
    if (! lineCallWithRef(ul, tunnelNextUpStreamInit, t))
    {
        return;
    }

    sbuf_t *handshake = bufferpoolGetLargeBuffer(lineGetBufferPool(ul));
    handshake         = sbufReserveSpace(handshake, ts->handshake_length);
    memoryCopy(sbufGetMutablePtr(handshake), ts->handshake_bytes, ts->handshake_length);
    sbufSetLength(handshake, ts->handshake_length);
    tunnelNextUpStreamPayload(t, ul, handshake);
}

void reverseclientInitiateConnectOnWorker(tunnel_t *t, wid_t wid, bool delay)
{
    discard delay;

    reverseclient_tstate_t *ts = tunnelGetState(t);
    if (atomicLoadRelaxed(&ts->stopping))
    {
        return;
    }

    reverseclient_thread_box_t *box = &ts->threadlocal_pool[wid];
    if (box->unused_cons_count + box->connecting_cons_count >= ts->min_unused_cons)
    {
        return;
    }
    box->connecting_cons_count++;

    if (UNLIKELY(
            sendWorkerMessageForceQueueWithCleanup(wid,
                                                   (WorkerMessageCallback) reverseclientBeginConnectMessageReceived,
                                                   reverseclientBeginConnectMessageCleanup,
                                                   t,
                                                   (void *) (uintptr_t) wid,
                                                   NULL) != kWorkerMessageSubmitAccepted))
    {
        if (atomicLoadRelaxed(&ts->stopping))
        {
            return;
        }
        if (! signalmanagerRequestShutdownPreservingAcceptedStatus(1))
        {
            abortProgramNow(1);
        }
        LOGF("ReverseClient: failed to admit required connection-start task on worker %u", (unsigned int) wid);
    }
}

void reverseclientOnStarvedConnectionExpire(idle_item_t *idle_con)
{
    reverseclient_pair_t *pair = idle_con->userdata;
    assert(pair != NULL);
    assert(pair->idle_handle == idle_con);
    assert(pair->phase != kReverseClientPairActive);

    pair->idle_handle = NULL;
    LOGW("ReverseClient: an idle connection was closed");
    reverseclientClosePair(pair, kReverseClientCloseIdleExpiry);
}
