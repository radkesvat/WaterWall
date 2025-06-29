#include "structure.h"

#include "loggers/network_logger.h"

void tundeviceTunnelDestroy(tunnel_t *t)
{
    tundevice_tstate_t *state = tunnelGetState(t);
    tun_device_t       *tdev  = state->tdev;

    if (! tundeviceBringDown(tdev))
    {
        LOGW("TunDevice: Bring down failed");
    }
    tundeviceDestroy(tdev);

    memoryFree(state->name);
    memoryFree(state->ip_subnet);
    memoryFree(state->ip_present);
    tunnelDestroy(t);
}

