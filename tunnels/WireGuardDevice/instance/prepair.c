#include "structure.h"

#include "loggers/network_logger.h"

static bool wireguarddeviceNeighborIsUdpStatelessSocket(const tunnel_t *neighbor)
{
    return (neighbor != NULL) && (neighbor->node != NULL) && (neighbor->node->type != NULL) &&
           (stringCompare(neighbor->node->type, "UdpStatelessSocket") == 0);
}

void wireguarddeviceTunnelOnPrepair(tunnel_t *t)
{
    wgd_tstate_t *state             = tunnelGetState(t);
    const bool    prev_is_transport = wireguarddeviceNeighborIsUdpStatelessSocket(t->prev);
    const bool    next_is_transport = wireguarddeviceNeighborIsUdpStatelessSocket(t->next);

    state->transport_side_is_next = true;

    if (prev_is_transport && ! next_is_transport)
    {
        state->transport_side_is_next = false;
    }
    else if (next_is_transport && ! prev_is_transport)
    {
        state->transport_side_is_next = true;
    }
}
