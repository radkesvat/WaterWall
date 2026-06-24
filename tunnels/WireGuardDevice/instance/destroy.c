#include "structure.h"

#include "loggers/network_logger.h"

void wireguarddeviceTunnelDestroy(tunnel_t *t)
{
    wgd_tstate_t *state = tunnelGetState(t);
    if (state->device_configuration.private_key != NULL)
    {
        memoryFree((void *) state->device_configuration.private_key);
        state->device_configuration.private_key = NULL;
    }
    if (state->transport_lines != NULL)
    {
        tunnel_chain_t *chain = tunnelGetChain(t);
        if (chain != NULL)
        {
            for (wid_t wi = 0; wi < chain->workers_count; ++wi)
            {
                if (state->transport_lines[wi] != NULL)
                {
                    LOGW("WireGuardDevice: transport line for worker %u was still alive during destroy",
                         (unsigned int) wi);
                }
            }
        }
        memoryFree(state->transport_lines);
        state->transport_lines = NULL;
    }
    mutexDestroy(&state->mutex);
    tunnelDestroy(t);
}
