#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpserverTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                    context;
    tcpoverudpserver_tstate_t *ts = tunnelGetState(t);
    atomicStoreRelaxed(&ts->stopping, true);
}

void tcpoverudpserverTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard                    context;
    tcpoverudpserver_tstate_t *ts = tunnelGetState(t);
    assert(currentThreadOwnsWorker(wid) && wid < ts->workers_count);
    tcpoverudpserver_worker_t *worker = &ts->workers[wid];
    worker->quiescing                 = true;
    for (tcpoverudpserver_carrier_t *carrier = worker->carriers; carrier != NULL; carrier = carrier->next)
    {
        if (carrier->pending_timer != NULL)
        {
            weventSetUserData(carrier->pending_timer, NULL);
            wtimerDelete(carrier->pending_timer);
            carrier->pending_timer = NULL;
        }
        for (tcpoverudpserver_session_t *session = carrier->sessions; session != NULL; session = session->next)
        {
            touSessionQuiesce(session->engine);
        }
    }
}

void tcpoverudpserverTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    tcpoverudpserverTunnelOnWorkerQuiesce(t, wid, context);
    tcpoverudpserver_tstate_t *ts = tunnelGetState(t);
    /* Each entry inventories our timers/sessions and every owned service, including detached drains. */
    while (ts->workers[wid].carriers != NULL)
    {
        tcpoverudpserverCarrierClose(ts->workers[wid].carriers, true);
    }
}

void tcpoverudpserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                    context;
    tcpoverudpserver_tstate_t *ts = tunnelGetState(t);
    for (wid_t wid = 0; wid < ts->workers_count; ++wid)
    {
        if (UNLIKELY(ts->workers[wid].carriers != NULL))
        {
            LOGF("TcpOverUdpServer: session/carrier roots remain at destruction");
            abortProgramNow(1);
        }
    }
    memoryFree(ts->workers);
    tunnelDestroy(t);
}
