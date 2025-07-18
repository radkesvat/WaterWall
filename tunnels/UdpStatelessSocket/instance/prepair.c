#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketTunnelOnPrepair(tunnel_t *t)
{
    udpstatelesssocket_tstate_t *state = tunnelGetState(t);

    if (nodeIsLastInChain(t->node))
    {
        state->WriteReceivedPacket = t->prev->fnPayloadD;
        state->write_tunnel = t->prev;
    }
    else
    {
        state->WriteReceivedPacket = t->next->fnPayloadU;
        state->write_tunnel = t->next;
    }

}
