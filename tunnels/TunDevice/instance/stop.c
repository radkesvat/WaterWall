#include "structure.h"

#include "loggers/network_logger.h"

void tundeviceTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard             context;
    tundevice_tstate_t *state = tunnelGetState(t);
    if (state->tdev != NULL && ! tundeviceRequestStop(state->tdev))
    {
        LOGW("TunDevice: failed to wake the device reader during quiescence");
        applicationShutdownRecordFailure(1, kApplicationShutdownReasonSubsystemFailure);
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

    if (state->pre_down_pending)
    {
        state->pre_down_pending = false;
        if (execCmd(state->pre_down_script).exit_code != 0)
        {
            LOGW("TunDevice: pre-down-script failed");
        }
    }
    tundeviceClearEgressPinIfPublished(state);
    tundeviceCleanupDnsSettings(state);
    tundeviceCleanupSystemRoutes(state);
    if (! tundeviceBringDown(tdev))
    {
        LOGW("TunDevice: Bring down failed");
        state->policy_cleanup_failed = true;
    }
    if (state->policy_cleanup_failed)
    {
        applicationShutdownRecordFailure(1, kApplicationShutdownReasonSubsystemFailure);
    }
}
