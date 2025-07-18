#include "structure.h"

#include "loggers/network_logger.h"

void tundeviceTunnelOnPrepair(tunnel_t *t)
{
    tundevice_tstate_t *state = tunnelGetState(t);
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

    state->tdev = tundeviceCreate(state->name, false, t, tundeviceOnIPPacketReceived);

    if (state->tdev == NULL)
    {
        LOGF("TunDevice: could not create device");
        terminateProgram(1);
    }

    tundeviceAssignIP(state->tdev, state->ip_present, (unsigned int) state->subnet_mask);

    tundeviceBringUp(state->tdev);
}
