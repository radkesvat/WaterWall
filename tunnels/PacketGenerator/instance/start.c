#include "structure.h"

#include "loggers/network_logger.h"

void packetgeneratorTunnelOnStart(tunnel_t *t)
{
    packetgenerator_tstate_t *state = tunnelGetState(t);

    atomicStoreRelaxed(&state->completed_workers, 0);
    state->schedule_start_ms = getHRTimeUs() / 1000U;

    for (wid_t wi = 0; wi < state->workers_count; ++wi)
    {
        if (UNLIKELY(sendWorkerMessageForceQueueWithCleanup(wi, packetgeneratorStartWorker, NULL, t, NULL, NULL) !=
                     kWorkerMessageSubmitAccepted))
        {
            LOGF("PacketGenerator: failed to admit required worker startup on worker %u", (unsigned int) wi);
            startupFailureRecord(1);
            return;
        }
    }
}
