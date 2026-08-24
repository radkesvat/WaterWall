#include "structure.h"

#include "loggers/network_logger.h"

void muxserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard             context;
    muxserver_tstate_t *ts = tunnelGetState(t);
    for (uint32_t wid = 0; wid < ts->workers_count; ++wid)
    {
        muxserver_worker_state_t      *worker_state = &ts->worker_states[wid];
        muxserver_detached_registry_t *registry     = &worker_state->detached_registry;
        if (UNLIKELY(registry->head != NULL || registry->count != 0 || registry->queued_bytes != 0))
        {
            LOGF("MuxServer: destroy observed a nonempty detached registry on worker %u", wid);
            abortProgramNow(1);
        }
        if (UNLIKELY(worker_state->child_idle_table != NULL))
        {
            LOGF("MuxServer: destroy observed an undestroyed child idle table on worker %u", wid);
            abortProgramNow(1);
        }
    }
    if (UNLIKELY(atomicLoadRelaxed(&ts->live_children_count) != 0))
    {
        LOGF("MuxServer: destroy observed %u live child reservation(s)",
             (unsigned int) atomicLoadRelaxed(&ts->live_children_count));
        abortProgramNow(1);
    }
    tunnelDestroy(t);
}
