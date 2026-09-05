#include "structure.h"

#include "loggers/network_logger.h"

void packetsenderTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadIsEventWorkerWID(wid));

    packetsender_tstate_t *state = tunnelGetState(t);
    if (state->workers == NULL || wid >= state->workers_count)
    {
        return;
    }

    packetsender_worker_state_t *slot = &state->workers[wid];
    packetsenderStopWorker(slot);
}
