#include "structure.h"

#include "loggers/network_logger.h"

static void tundeviceTunnelStopDevice(tundevice_tstate_t *state)
{
    tun_device_t *tdev = state->tdev;

    if (tundeviceIsUp(tdev))
    {
        if (state->pre_down_script != NULL && execCmd(state->pre_down_script).exit_code != 0)
        {
            LOGW("TunDevice: pre-down-script failed");
        }
        tundeviceClearEgressPinIfPublished(state);
        tundeviceCleanupDnsSettings(state);
        tundeviceCleanupSystemRoutes(state);
        if (! tundeviceBringDown(tdev))
        {
            LOGW("TunDevice: Bring down failed");
        }
    }
}

void tundeviceTunnelOnStop(tunnel_t *t)
{
    tundeviceTunnelStopDevice(tunnelGetState(t));
}
