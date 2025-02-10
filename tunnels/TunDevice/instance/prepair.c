#include "structure.h"

#include "loggers/network_logger.h"

void tundeviceTunnelOnPrepair(tunnel_t *t)
{
    tundevice_tstate_t * state = tunnelGetState(t);

    tundeviceAssignIP(state->tdev, state->ip_present, state->subnet_mask);

    tundeviceBringUp(state->tdev);
}
