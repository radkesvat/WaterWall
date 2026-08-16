#include "structure.h"

#include "loggers/network_logger.h"

void testerclientTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    discard t;
}

void testerclientTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard                      context;
    testerclient_tstate_t       *ts   = tunnelGetState(t);
    testerclient_worker_state_t *slot = &ts->workers[wid];

    if (ts->packet_mode || slot->line == NULL || slot->closed)
    {
        return;
    }

    line_t *l = slot->line;
    assert(currentThreadIsEventWorkerWID(wid));
    assert(lineGetWID(l) == wid);

    lineLock(l);
    slot->line            = NULL;
    slot->close_scheduled = true;
    slot->closed          = true;

    testerclient_lstate_t *ls = lineGetState(l, t);
    testerclientLinestateDestroy(ls);
    if (lineIsAlive(l))
    {
        tunnelNextUpStreamFinish(t, l);
    }
    if (lineIsAlive(l))
    {
        lineDestroy(l);
    }
    lineUnlock(l);
}
