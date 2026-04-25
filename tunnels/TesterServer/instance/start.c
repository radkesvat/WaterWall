#include "structure.h"

#include "loggers/network_logger.h"

static void testerserverStartPacketWorker(void *worker, void *arg1, void *arg2, void *arg3)
{
    worker_t              *real_worker = worker;
    tunnel_t              *t           = arg1;
    wid_t                  wid         = real_worker->wid;
    line_t                *l           = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), wid);
    testerserver_lstate_t *ls          = lineGetState(l, t);

    discard arg2;
    discard arg3;

    if (ls->read_stream.pool != NULL)
    {
        return;
    }

    testerserverLinestateInitialize(ls, lineGetBufferPool(l));
}

void testerserverTunnelOnStart(tunnel_t *t)
{
    testerserver_tstate_t *ts = tunnelGetState(t);

    if (! (ts->packet_mode && ts->packet_init_on_start))
    {
        return;
    }

    tunnel_chain_t *tc = tunnelGetChain(t);

    for (wid_t wi = 0; wi < tc->workers_count; ++wi)
    {
        sendWorkerMessageForceQueue(wi, testerserverStartPacketWorker, t, NULL, NULL);
    }
}
