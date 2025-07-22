#include "structure.h"

#include "loggers/network_logger.h"

static void reverseclientBeginConnectMessageReceived(worker_t *worker, void *arg1, void *arg2, void *arg3)
{

    discard arg2;
    discard arg3;

    tunnel_t               *t  = (tunnel_t *) arg1;
    reverseclient_tstate_t *ts = tunnelGetState(t);

    wid_t wid = worker->wid;

    line_t *ul = lineCreate(tunnelchainGetLinePool(tunnelGetChain(t), wid), wid);
    line_t *dl = lineCreate(tunnelchainGetLinePool(tunnelGetChain(t), wid), wid);

    reverseclient_lstate_t *uls = lineGetState(ul, t);
    reverseclient_lstate_t *dls = lineGetState(dl, t);

    reverseclientLinestateInitialize(uls, t, ul, dl);
    reverseclientLinestateInitialize(dls, t, ul, dl);

    uls->idle_handle = idleItemNew(ts->starved_connections, (hash_t) (uintptr_t) (uls), uls, reverseclientOnStarvedConnectionExpire,
                                   wid, ((uint64_t) (kConnectionStarvationTimeOutSec) * 1000));

    lineLock(ul);

    tunnelNextUpStreamInit(t, ul);

    if (! lineIsAlive(ul))
    {
        lineUnlock(ul);
        return;
    }
    lineUnlock(ul);

    sbuf_t* handshakebuf = bufferpoolGetLargeBuffer(lineGetBufferPool(ul));
    sbufReserveSpace(handshakebuf, kHandShakeLength);
    memorySet(sbufGetMutablePtr(handshakebuf), kHandShakeByte, kHandShakeLength);
    sbufSetLength(handshakebuf, kHandShakeLength);

    tunnelNextUpStreamPayload(t, ul, handshakebuf);
}

void reverseclientInitiateConnectOnWorker(tunnel_t *t, wid_t wid, bool delay)
{
    discard delay;

    reverseclient_tstate_t *ts = tunnelGetState(t);

    if (ts->threadlocal_pool[wid].unused_cons_count + ts->threadlocal_pool[wid].connecting_cons_count >=
        ts->min_unused_cons)
    {
        return;
    }
    ts->threadlocal_pool[wid].connecting_cons_count += 1;

    sendWorkerMessageForceQueue(wid, reverseclientBeginConnectMessageReceived, t, NULL, NULL);
}

void reverseclientOnStarvedConnectionExpire(widle_item_t *idle_con)
{
    reverseclient_lstate_t *ls = idle_con->userdata;

    tunnel_t               *t  = ls->t;
    reverseclient_tstate_t *ts = tunnelGetState(t);

    if (ls->idle_handle == NULL)
    {
        LOGF("ReverseClient: onStarvedConnectionExpire called with NULL idle_handle");
        terminateProgram(1);
        return;
    }
    ls->idle_handle = NULL;

    assert(! ls->pair_connected);

    line_t *ul = ls->u;
    line_t *dl = ls->d;

    ts->threadlocal_pool[lineGetWID(ul)].unused_cons_count -= 1;
    LOGW("ReverseClient: a idle connection detected and closed");

    reverseclientInitiateConnectOnWorker(t, lineGetWID(ul), false);

    tunnelNextUpStreamFinish(t, ul);

    reverseclientLinestateDestroy(ls);
    reverseclientLinestateDestroy(lineGetState(dl, t));

    lineDestroy(ul);
    lineDestroy(dl);
}
