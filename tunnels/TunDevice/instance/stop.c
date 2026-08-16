#include "structure.h"

#include "loggers/network_logger.h"

void tundeviceTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard             context;
    tundevice_tstate_t *state = tunnelGetState(t);
    if (state->tdev != NULL && ! tundeviceRequestStop(state->tdev))
    {
        LOGW("TunDevice: failed to wake the device reader during quiescence");
    }
}

void tundeviceTunnelOnQuiesceWait(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard             context;
    tundevice_tstate_t *state = tunnelGetState(t);
    tun_device_t       *tdev  = state->tdev;

    if (tdev == NULL)
    {
        return;
    }

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
