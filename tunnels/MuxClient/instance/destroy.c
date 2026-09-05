#include "structure.h"

#include "loggers/network_logger.h"

void muxclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard             context;
    muxclient_tstate_t *ts = tunnelGetState(t);

    for (uint32_t wid = 0; wid < ts->workers_count; ++wid)
    {
        if (UNLIKELY(ts->worker_states[wid].owned_parents != NULL || ts->unsatisfied_lines[wid] != NULL))
        {
            LOGF("MuxClient: destroy observed a published parent on worker %u", wid);
            abortProgramNow(1);
        }
        if (UNLIKELY(ts->detached_child_counts == NULL || ts->detached_queued_charge == NULL ||
                     ts->detached_child_counts[wid] != 0 || ts->detached_queued_charge[wid] != 0))
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
    if (ts->fixed_next_parent_indexes != NULL)
    {
        memoryFree(ts->fixed_next_parent_indexes);
    }
    memoryFree(ts->worker_states);
    memoryFree(ts->detached_child_counts);
    memoryFree(ts->detached_queued_charge);
    tunnelDestroy(t);
}
