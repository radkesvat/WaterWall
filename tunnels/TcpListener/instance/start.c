#include "structure.h"

#include "loggers/network_logger.h"

void tcplistenerTunnelOnStart(tunnel_t *t)
{
    tcplistener_tstate_t *state   = tunnelGetState(t);
    const tunnel_chain_t *chain   = tunnelGetChain(t);
    bool                  changed = false;

    if (chain->mux_client_tunnel_present || chain->mux_server_tunnel_present)
    {
        const int buffer_size =
            chain->mux_server_tunnel_present ? kDefaultLargeSocketBufferSize : kDefaultLargeSocketBufferSize / 16;
        if (! state->send_buffer_size_set)
        {
            state->send_buffer_size = buffer_size;
            changed                 = true;
        }
        if (! state->recv_buffer_size_set)
        {
            state->recv_buffer_size = buffer_size;
            changed                 = true;
        }
    }

    if (changed)
    {
        socketacceptorUpdateBufferOptions(t, state->send_buffer_size, state->recv_buffer_size);
    }
}
