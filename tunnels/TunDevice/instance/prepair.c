#include "structure.h"

#include "loggers/network_logger.h"

void tundeviceTunnelOnPrepair(tunnel_t *t)
{
    tundevice_tstate_t * state = tunnelGetState(t);

    state->tdev = tundeviceCreate(state->name, false, t, tundeviceOnIPPacketReceived);

    if (state->tdev == NULL)
    {
        LOGF("TunDevice: could not create device");
        exit(1);
    }

    tundeviceAssignIP(state->tdev, state->ip_present, (unsigned int )state->subnet_mask);

    tundeviceBringUp(state->tdev);
}
