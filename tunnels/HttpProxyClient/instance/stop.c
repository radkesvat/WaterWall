#include "structure.h"
void httpproxyclientTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadIsEventWorkerWID(wid));
    hpc_tstate_t *ts           = tunnelGetState(t);
    ts->workers[wid].quiescing = true;
    while (ts->workers[wid].timers)
        hpcDetachTimer(ts->workers[wid].timers);
}
