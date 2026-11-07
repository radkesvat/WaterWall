#include "structure.h"

#include "loggers/network_logger.h"

void kcpserverTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard             context;
    kcpserver_tstate_t *ts = tunnelGetState(t);
    atomicStoreRelaxed(&ts->stopping, true);
}

void kcpserverTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard             context;
    kcpserver_tstate_t *ts = tunnelGetState(t);
    assert(currentThreadOwnsWorker(wid) && wid < ts->workers_count);
    kcpserver_worker_t *worker = &ts->workers[wid];
    worker->quiescing          = true;
    for (kcpserver_carrier_t *carrier = worker->carriers; carrier != NULL; carrier = carrier->next)
    {
        if (carrier->pending_timer != NULL)
        {
            weventSetUserData(carrier->pending_timer, NULL);
            wtimerDelete(carrier->pending_timer);
            carrier->pending_timer = NULL;
        }
        for (kcpserver_session_t *session = carrier->sessions; session != NULL; session = session->next)
        {
            touSessionQuiesce(session->engine);
        }
    }
}

void kcpserverTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    kcpserverTunnelOnWorkerQuiesce(t, wid, context);
    kcpserver_tstate_t *ts = tunnelGetState(t);
    /* Each entry inventories our timers/sessions and every owned service, including detached drains. */
    while (ts->workers[wid].carriers != NULL)
    {
        kcpserverCarrierClose(ts->workers[wid].carriers, true);
    }
}

void kcpserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard             context;
    kcpserver_tstate_t *ts = tunnelGetState(t);
    for (wid_t wid = 0; wid < ts->workers_count; ++wid)
    {
        if (UNLIKELY(ts->workers[wid].carriers != NULL))
        {
            LOGF("KcpServer: session/carrier roots remain at destruction");
            abortProgramNow(1);
        }
    }
    memoryFree(ts->workers);
    tunnelDestroy(t);
}
