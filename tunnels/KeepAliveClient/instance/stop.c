#include "structure.h"

void keepaliveclientTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadIsEventWorkerWID(wid));

    keepaliveclient_tstate_t       *ts    = tunnelGetState(t);
    keepaliveclient_worker_state_t *state = &ts->worker_states[wid];
    state->quiesced                       = true;
    if (state->idle_table != NULL)
    {
        localidletableQuiesce(state->idle_table);
        if (state->active_lines == 0)
        {
            localidletableDestroy(state->idle_table);
            state->idle_table = NULL;
        }
    }
}
