#include "structure.h"

#include "loggers/network_logger.h"

void muxserverTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard             context;
    muxserver_tstate_t *ts = tunnelGetState(t);
    if (UNLIKELY(atomicLoadRelaxed(&ts->live_children_count) != 0))
    {
        LOGF("MuxServer: stop observed %u live child reservation(s)",
             (unsigned int) atomicLoadRelaxed(&ts->live_children_count));
        abortProgramNow(1);
    }
}

void muxserverTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadIsEventWorkerWID(wid));

    muxserver_tstate_t *ts = tunnelGetState(t);
    if (UNLIKELY(wid >= ts->workers_count))
    {
        LOGF("MuxServer: invalid worker %d during child idle-table quiescence", (int) wid);
        abortProgramNow(1);
    }
    local_idle_table_t *table = ts->worker_states[wid].child_idle_table;
    if (table != NULL)
    {
        localidletableQuiesce(table);
    }
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

    muxserver_worker_state_t      *worker_state = &ts->worker_states[wid];
    muxserver_detached_registry_t *registry     = &worker_state->detached_registry;
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

    if (UNLIKELY(registry->count != 0 || registry->queued_bytes != 0))
    {
        LOGF("MuxServer: worker %d detached registry accounting remained after drain (count=%u, bytes=%zu)",
             (int) wid,
             (unsigned int) registry->count,
             registry->queued_bytes);
        abortProgramNow(1);
    }

    if (worker_state->child_idle_table != NULL)
    {
        if (UNLIKELY(localidletableGetItemCount(worker_state->child_idle_table) != 0))
        {
            LOGF("MuxServer: worker %d stopped with %zu child idle item(s)",
                 (int) wid,
                 localidletableGetItemCount(worker_state->child_idle_table));
            abortProgramNow(1);
        }
        localidletableDestroy(worker_state->child_idle_table);
        worker_state->child_idle_table = NULL;
    }
}
