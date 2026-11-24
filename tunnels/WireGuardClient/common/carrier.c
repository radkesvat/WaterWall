#include "loggers/network_logger.h"
#include "structure.h"

line_t *wireguardclientEnsureCarrier(wireguardclient_tstate_t *state)
{
    assert(currentThreadOwnsWorker(0));
    line_t *line = state->carrier;
    if (LIKELY(line != NULL))
    {
        const wireguardclient_carrier_phase_t *phase = lineGetState(line, state->tunnel);
        return *phase == kCarrierOpen ? line : NULL;
    }
    const uint32_t now = getTickMS();
    if (! atomicLoad(&state->dispatch.open) || (state->attempted && now - state->last_attempt < 400))
        return NULL;
    state->attempted    = true;
    state->last_attempt = now;
    if (UNLIKELY(state->carrier_id == UINT64_MAX))
    {
        LOGF("WireGuardClient: carrier identity exhausted");
        abortProgramNow(1);
    }
    ++state->carrier_id;
    line                                   = lineCreate(tunnelchainGetLinePools(state->tunnel->chain), 0);
    state->carrier                         = line;
    wireguardclient_carrier_phase_t *phase = lineGetState(line, state->tunnel);
    *phase                                 = kCarrierStarting;
    state->paused                          = false;
    addresscontextCopy(lineGetDestinationAddressContext(line), &state->endpoint);
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(line), IP_PROTO_UDP);
    if (! lineCallWithRef(line, tunnelNextUpStreamInit, state->tunnel) || state->carrier != line)
        return NULL;
    *phase = kCarrierOpen;
    return line;
}
