#include "structure.h"

#include "loggers/network_logger.h"

void keepaliveclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                   context;
    keepaliveclient_tstate_t *ts = tunnelGetState(t);

    /* KeepAliveClient is strictly L4 and borrows every line. All real owners
     * must have completed their drains before final instance destruction. This
     * terminal check is safe even when the chain array itself is not stored in
     * source-to-tail order. */
    for (wid_t wid = 0; wid < getWorkersCount(); ++wid)
    {
        if (UNLIKELY(ts->worker_states[wid].active_lines != 0 || ts->worker_states[wid].idle_table != NULL))
        {
            LOGF("KeepAliveClient: tunnel destruction found a tracked line or idle table on worker %u",
                 (unsigned int) wid);
            abortProgramNow(1);
        }
    }

    tunnelDestroy(t);
}
