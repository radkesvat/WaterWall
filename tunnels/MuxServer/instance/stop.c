#include "structure.h"

#include "loggers/network_logger.h"

void muxserverTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    discard t;
}

void muxserverTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadIsEventWorkerWID(wid));

    muxserver_tstate_t *ts = tunnelGetState(t);
    if (UNLIKELY(wid >= ts->workers_count))
    {
        LOGF("MuxServer: invalid worker %d during detached child drain", (int) wid);
        abortProgramNow(1);
    }

    muxserver_detached_registry_t *registry = &ts->detached_registries[wid];
    if (registry->head != NULL && registry->queued_bytes != 0)
    {
        LOGW("MuxServer: worker stop is discarding %zu byte(s) from %u detached child line(s) on worker %d",
             registry->queued_bytes,
             registry->count,
             (int) wid);
    }

    while (registry->head != NULL)
    {
        muxserver_lstate_t *child_ls = registry->head;
        line_t             *child_l  = child_ls->l;
        if (UNLIKELY(lineGetWID(child_l) != wid))
        {
            LOGF("MuxServer: detached registry contains a child from worker %d in worker %d",
                 (int) lineGetWID(child_l),
                 (int) wid);
            abortProgramNow(1);
        }

        // Shutdown never creates more child Payload work; retained Mux buffers are released by state destruction.
        muxserverAbortDetachedChild(t, child_l, child_ls, true);
    }

    assert(registry->count == 0);
    assert(registry->queued_bytes == 0);
}
