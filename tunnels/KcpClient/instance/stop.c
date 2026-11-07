#include "structure.h"

#include "loggers/network_logger.h"

void kcpclientTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard             context;
    kcpclient_tstate_t *ts = tunnelGetState(t);
    atomicStoreRelaxed(&ts->stopping, true);
}

void kcpclientTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard             context;
    kcpclient_tstate_t *ts = tunnelGetState(t);
    assert(currentThreadOwnsWorker(wid) && wid < ts->workers_count);
    ts->workers[wid].quiescing = true;
    for (kcpclient_session_t *s = ts->workers[wid].sessions; s != NULL; s = s->next)
        touSessionQuiesce(s->driver);
}

void kcpclientTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    kcpclientTunnelOnWorkerQuiesce(t, wid, context);
    kcpclient_tstate_t *ts = tunnelGetState(t);
    while (ts->workers[wid].sessions != NULL)
        touSessionAbort(ts->workers[wid].sessions->driver, kTouAborted);
}

void kcpclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard             context;
    kcpclient_tstate_t *ts = tunnelGetState(t);
    for (wid_t wid = 0; wid < ts->workers_count; ++wid)
    {
        if (UNLIKELY(ts->workers[wid].sessions != NULL))
        {
            LOGF("KcpClient: owned transports remain at destruction");
            abortProgramNow(1);
        }
    }
    memoryFree(ts->workers);
    tunnelDestroy(t);
}
