#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpclientTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                    context;
    tcpoverudpclient_tstate_t *ts = tunnelGetState(t);
    atomicStoreRelaxed(&ts->stopping, true);
}

void tcpoverudpclientTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard                    context;
    tcpoverudpclient_tstate_t *ts = tunnelGetState(t);
    assert(currentThreadOwnsWorker(wid) && wid < ts->workers_count);
    ts->workers[wid].quiescing = true;
    for (tcpoverudpclient_session_t *s = ts->workers[wid].sessions; s != NULL; s = s->next)
        touSessionQuiesce(s->driver);
}

void tcpoverudpclientTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    tcpoverudpclientTunnelOnWorkerQuiesce(t, wid, context);
    tcpoverudpclient_tstate_t *ts = tunnelGetState(t);
    while (ts->workers[wid].sessions != NULL)
        touSessionAbort(ts->workers[wid].sessions->driver, kTouAborted);
}

void tcpoverudpclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                    context;
    tcpoverudpclient_tstate_t *ts = tunnelGetState(t);
    for (wid_t wid = 0; wid < ts->workers_count; ++wid)
    {
        if (UNLIKELY(ts->workers[wid].sessions != NULL))
        {
            LOGF("TcpOverUdpClient: owned transports remain at destruction");
            abortProgramNow(1);
        }
    }
    memoryFree(ts->workers);
    tunnelDestroy(t);
}
