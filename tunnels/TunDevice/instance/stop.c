#include "structure.h"

#include "loggers/network_logger.h"

static void tundeviceTunnelStopDevice(tundevice_tstate_t *state)
{
    tun_device_t *tdev = state->tdev;

    if (tdev && tdev->up)
    {
        if (state->pre_down_script != NULL && execCmd(state->pre_down_script).exit_code != 0)
        {
            LOGW("TunDevice: pre-down-script failed");
        }
        tunLoopGuardStop(state->loop_guard);
        state->loop_guard = NULL;
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
