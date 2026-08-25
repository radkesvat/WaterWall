#include "structure.h"

#include "loggers/network_logger.h"

void udplistenerTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard               context;
    udplistener_tstate_t *state = tunnelGetState(t);

    if (state->worker_registries != NULL)
    {
        for (wid_t wid = 0; wid < state->workers_count; ++wid)
        {
            assert(udplistener_endpoint_map_t_size(&state->worker_registries[wid].endpoints) == 0);
            udplistener_endpoint_map_t_drop(&state->worker_registries[wid].endpoints);
        }
        memoryFree(state->worker_registries);
        state->worker_registries = NULL;
    }

    vec_ipmask_t_drop(&state->white_list);
    vec_ipmask_t_drop(&state->black_list);

    if (state->interface_name != NULL)
    {
        memoryFree(state->interface_name);
        state->interface_name = NULL;
    }

    if (state->listen_address != NULL)
    {
        memoryFree(state->listen_address);
        state->listen_address = NULL;
    }

    tunnelDestroy(t);
}
