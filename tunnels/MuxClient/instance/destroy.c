#include "structure.h"

#include "loggers/network_logger.h"

void muxclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard             context;
    muxclient_tstate_t *ts = tunnelGetState(t);

    for (uint32_t wid = 0; wid < ts->workers_count; ++wid)
    {
        if (UNLIKELY(ts->worker_states[wid].owned_parents != NULL || ts->worker_states[wid].unsatisfied_line != NULL ||
                     ts->worker_states[wid].stall_retired_parents != 0 ||
                     ts->worker_states[wid].keepalive_table != NULL))
        {
            LOGF("MuxClient: destroy observed a published parent on worker %u", wid);
            abortProgramNow(1);
        }
        if (UNLIKELY(ts->worker_states[wid].detached_child_count != 0 ||
                     ts->worker_states[wid].detached_queued_charge != 0))
        {
            LOGF("MuxClient: destroy observed detached borrowed children on worker %u", wid);
            abortProgramNow(1);
        }
    }

    for (size_t i = 0; i < (size_t) ts->workers_count * ts->fixed_connections_count; ++i)
    {
        if (UNLIKELY(ts->fixed_parent_lines[i] != NULL))
        {
            LOGF("MuxClient: destroy observed a selected fixed parent");
            abortProgramNow(1);
        }
    }

    if (ts->fixed_parent_lines != NULL)
    {
        memoryFree(ts->fixed_parent_lines);
    }
    tunnelDestroy(t);
}
