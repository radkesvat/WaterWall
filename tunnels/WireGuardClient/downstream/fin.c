#include "loggers/network_logger.h"
#include "structure.h"

void wireguardclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    wireguardclient_tstate_t *state = tunnelGetState(t);
    assert(currentThreadOwnsWorker(0) && ! tunnelchainIsWorkerPacketLine(t->chain, l));
    wireguardclient_carrier_phase_t *phase = lineGetState(l, t);
    if (UNLIKELY(*phase == kCarrierUnused))
    {
        LOGF("WireGuardClient: Finish reached a normal line outside its carrier inventory");
        abortProgramNow(1);
    }
    memoryZeroAligned32(phase, t->lstate_size);
    if (state->carrier == l)
    {
        state->carrier = NULL;
        state->paused  = false;
    }
    lineDestroy(l);
}
