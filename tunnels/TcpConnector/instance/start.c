#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorTunnelOnStart(tunnel_t *t)
{
    tcpconnector_tstate_t *state = tunnelGetState(t);

    if (tunnelGetChain(t)->mux_tunnel_present)
    {
        if (! state->send_buffer_size_set)
        {
            state->send_buffer_size = kDefaultLargeSocketBufferSize;
        }
        if (! state->recv_buffer_size_set)
        {
            state->recv_buffer_size = kDefaultLargeSocketBufferSize;
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

    if (state->address_probe_interval_ms > 0 && state->probe_timer == NULL)
    {
        state->probe_timer =
            wtimerAdd(getWorkerLoop(0), tcpconnectorProbeTimerCallback, state->address_probe_interval_ms, INFINITE);
        if (state->probe_timer == NULL)
        {
            LOGF("TcpConnector: failed to create address probe timer");
            terminateProgram(1);
        }
        weventSetUserData(state->probe_timer, t);
    }
}
