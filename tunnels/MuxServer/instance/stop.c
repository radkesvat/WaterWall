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
    ts->worker_states[wid].quiescing = true;
    local_idle_table_t *table = ts->worker_states[wid].child_idle_table;
    if (table != NULL)
    {
        localidletableQuiesce(table);
    }
}

void muxserverTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    muxserverTunnelOnWorkerQuiesce(t, wid, context);
    muxserver_tstate_t *ts = tunnelGetState(t);

    muxserver_worker_state_t      *worker_state = &ts->worker_states[wid];
    muxserver_detached_registry_t *registry     = &worker_state->detached_registry;
    if (worker_state->child_idle_table != NULL)
    {
        localidletableDrainItems(worker_state->child_idle_table);
    }

    if (UNLIKELY(registry->head != NULL || registry->count != 0 || registry->queued_charge != 0))
    {
        LOGF("MuxServer: worker %d detached registry accounting remained after drain "
             "(count=%u retained-charge=%zu)",
             (int) wid,
             (unsigned int) registry->count,
             registry->queued_charge);
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
