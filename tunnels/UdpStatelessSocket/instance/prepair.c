#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketTunnelOnPrepair(tunnel_t *t)
{
    udpstatelesssocket_tstate_t *state = tunnelGetState(t);

    if (nodeIsLastInChain(t->node))
    {
        state->WriteReceivedPacket = t->prev->fnPayloadD;
    }
    else
    {
        state->WriteReceivedPacket = t->next->fnPayloadU;
    }

}
