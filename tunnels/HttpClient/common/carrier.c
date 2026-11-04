#include "structure.h"

bool httpclientUsesOwnedCarrier(const httpclient_tstate_t *ts)
{
    if (ts->version_mode == kHttpClientVersionModeHttp1)
        return false;
    if (ts->version_mode == kHttpClientVersionModeBoth && ts->enable_upgrade)
    {
        if (ts->websocket_enabled)
            return false;
        if (ts->upgrade_protocol != NULL && ts->upgrade_protocol[0] != '\0' &&
            ! stringAsciiCaseEquals(ts->upgrade_protocol, "h2c"))
            return false;
    }
    return true;
}

void httpclientCarrierUnlink(httpclient_lstate_t *ls)
{
    if (ls->line_role != kHttpClientLineCarrier)
        return;
    httpclient_tstate_t *ts  = tunnelGetState(ls->tunnel);
    const wid_t          wid = lineGetWID(ls->line);
    assert(currentThreadOwnsWorker(wid) && wid < ts->worker_count);
    if (ls->inventory_prev != NULL)
        ls->inventory_prev->inventory_next = ls->inventory_next;
    else
    {
        assert(ts->carrier_heads[wid] == ls);
        ts->carrier_heads[wid] = ls->inventory_next;
    }
    if (ls->inventory_next != NULL)
        ls->inventory_next->inventory_prev = ls->inventory_prev;
}

void httpclientCarrierClose(tunnel_t *t, line_t *carrier, bool notify_application)
{
    httpclient_lstate_t *ls = lineGetState(carrier, t);
    assert(ls->line_role == kHttpClientLineCarrier);
    lineRef(carrier);
    line_t *application = ls->application_line;
    bool    send_next   = ! ls->next_finished;
    if (application != NULL)
    {
        lineRef(application);
        httpclient_lstate_t *app_ls = lineGetState(application, t);
        assert(app_ls->carrier_line == carrier);
        app_ls->carrier_line = NULL;
        ls->application_line = NULL;
        httpclientLinestateDestroy(app_ls);
    }
    httpclientLinestateDestroy(ls);
    if (send_next)
        tunnelNextUpStreamFinish(t, carrier);
    lineDestroy(carrier);
    if (application != NULL)
    {
        if (notify_application && lineIsAlive(application))
            tunnelPrevDownStreamFinish(t, application);
        lineUnref(application);
    }
    lineUnref(carrier);
}

void httpclientCarrierStart(tunnel_t *t, line_t *application)
{
    httpclient_tstate_t *ts     = tunnelGetState(t);
    httpclient_lstate_t *app_ls = lineGetState(application, t);
    const wid_t          wid    = lineGetWID(application);
    httpclientLinestateInitialize(app_ls, t, application);
    if (atomicLoadRelaxed(&ts->stopping) || ! wloopNormalDispatchAllowed(getWorkerLoop(wid)))
    {
        httpclientLinestateDestroy(app_ls);
        tunnelPrevDownStreamFinish(t, application);
        return;
    }

    line_t              *carrier = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), wid);
    httpclient_lstate_t *ls      = lineGetState(carrier, t);
    httpclientLinestateInitialize(ls, t, carrier);
    app_ls->line_role       = kHttpClientLineApplication;
    app_ls->carrier_line    = carrier;
    ls->line_role           = kHttpClientLineCarrier;
    ls->application_line    = application;
    ls->startup_in_progress = true;

    routing_context_t *source      = lineGetRoutingContext(application);
    routing_context_t *destination = lineGetRoutingContext(carrier);
    addresscontextCopy(&destination->src_ctx, &source->src_ctx);
    addresscontextCopy(&destination->dest_ctx, &source->dest_ctx);
    destination->local_listener_port = source->local_listener_port;
    destination->peer_source_port    = source->peer_source_port;
    lineCopyUsers(carrier, application);

    assert(wid < ts->worker_count);
    ls->inventory_next = ts->carrier_heads[wid];
    if (ls->inventory_next != NULL)
        ls->inventory_next->inventory_prev = ls;
    ts->carrier_heads[wid] = ls;

    lineRef(carrier);
    httpclientStartTransport(t, carrier);
    if (lineIsAlive(carrier))
    {
        ls->startup_in_progress = false;
        if (! httpclientTransportFlushPendingUp(t, carrier, ls))
        {
            if (lineIsAlive(carrier))
                httpclientCarrierClose(t, carrier, true);
        }
        else if (lineIsAlive(carrier))
            httpclientProgressClose(t, carrier, ls);
    }
    lineUnref(carrier);
}

void httpclientTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard              context;
    httpclient_tstate_t *ts = tunnelGetState(t);
    atomicStoreRelaxed(&ts->stopping, true);
}

void httpclientTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadOwnsWorker(wid));
    httpclient_tstate_t *ts = tunnelGetState(t);
    while (ts->carrier_heads[wid] != NULL)
        httpclientCarrierClose(t, ts->carrier_heads[wid]->line, true);
}
