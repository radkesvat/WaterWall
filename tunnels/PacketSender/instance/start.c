#include "structure.h"

#include "loggers/network_logger.h"

void packetsenderTunnelOnStart(tunnel_t *t)
{
    packetsender_tstate_t *state = tunnelGetState(t);

    atomicStoreRelaxed(&state->completed_workers, 0);
    state->schedule_start_ms = getHRTimeUs() / 1000U;

    for (wid_t wi = 0; wi < state->workers_count; ++wi)
    {
        sendWorkerMessageForceQueue(wi, packetsenderStartWorker, t, NULL, NULL);
    }
}
