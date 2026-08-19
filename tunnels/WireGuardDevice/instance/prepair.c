#include "structure.h"

#include "loggers/network_logger.h"

void wireguarddeviceTunnelOnPrepair(tunnel_t *t)
{
    const wgd_tstate_t *state = tunnelGetState(t);

    if (! state->transport_side_resolved)
    {
        LOGF("WireGuardDevice: transport and packet sides were not resolved before preparation");
        startupFailureRecord(1);
    }
}
