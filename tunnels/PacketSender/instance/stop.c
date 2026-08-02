#include "structure.h"

#include "loggers/network_logger.h"

void packetsenderTunnelOnStop(tunnel_t *t)
{
    discard t;
}

void packetsenderTunnelOnWorkerStop(tunnel_t *t, wid_t wid)
{
    // onWorkerStop runs on the worker being stopped, for its own slot only.
    assert(currentThreadIsEventWorkerWID(wid));

    packetsender_tstate_t *state = tunnelGetState(t);
    if (state->workers == NULL || wid >= state->workers_count)
    {
        return;
    }

    packetsender_worker_state_t *slot = &state->workers[wid];
    packetsenderStopWorker(slot);
}
