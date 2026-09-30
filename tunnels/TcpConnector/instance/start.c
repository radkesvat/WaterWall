#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorTunnelOnStart(tunnel_t *t)
{
    tcpconnector_tstate_t *state = tunnelGetState(t);
    const tunnel_chain_t  *chain = tunnelGetChain(t);

    if (! (chain->mux_client_tunnel_present || chain->mux_server_tunnel_present))
    {
        return;
    }

    const int buffer_size =
        chain->mux_client_tunnel_present ? kDefaultLargeSocketBufferSize : kDefaultLargeSocketBufferSize / 16;
    if (! state->send_buffer_size_set)
    {
        state->send_buffer_size = buffer_size;
    }
    if (! state->recv_buffer_size_set)
    {
        state->recv_buffer_size = buffer_size;
    }

    for (uint32_t i = 0; i < state->destinations_count; ++i)
    {
        tcpconnector_destination_t *destination = &state->destinations[i];
        if (! destination->send_buffer_size_set)
        {
            destination->send_buffer_size = state->send_buffer_size;
        }
        if (! destination->recv_buffer_size_set)
        {
            destination->recv_buffer_size = state->recv_buffer_size;
        }
    }
}
