#include "structure.h"

#include "loggers/network_logger.h"

void tcplistenerTunnelOnStart(tunnel_t *t)
{
    tcplistener_tstate_t *state   = tunnelGetState(t);
    const tunnel_chain_t *chain   = tunnelGetChain(t);
    bool                  changed = false;

    if (! GSTATE.tcp_tune_enabled && (chain->mux_client_tunnel_present || chain->mux_server_tunnel_present))
    {
        if (! state->send_buffer_size_set)
        {
            state->send_buffer_size = kDefaultLargeSocketBufferSize;
            changed                 = true;
        }
        if (! state->recv_buffer_size_set)
        {
            state->recv_buffer_size = kDefaultLargeSocketBufferSize;
            changed                 = true;
        }
    }

    if (changed)
    {
        socketacceptorUpdateBufferOptions(t, state->send_buffer_size, state->recv_buffer_size);
    }
}
