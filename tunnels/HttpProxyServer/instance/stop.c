#include "structure.h"

void httpproxyserverTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadIsEventWorkerWID(wid));
    hps_tstate_t *ts = tunnelGetState(t);
    hps_worker_t *w  = &ts->workers[wid];
    w->quiescing     = true;
    while (w->timers)
        hpsDetachTimer(w->timers);
}

void httpproxyserverTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    httpproxyserverTunnelOnWorkerQuiesce(t, wid, context);
    hps_tstate_t *ts = tunnelGetState(t);
    while (ts->workers[wid].children)
    {
        hps_session_t *s = ts->workers[wid].children->session;
        hpsRetain(s);
        hpsCloseChild(s, false);
        /* The borrowed client's owner will close it; its slot remains valid until then. */
        hpsRelease(s);
    }
}
