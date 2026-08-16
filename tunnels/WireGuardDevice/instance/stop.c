#include "structure.h"

#include "loggers/network_logger.h"

void wireguarddeviceTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    discard t;
}

void wireguarddeviceTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadIsEventWorkerWID(wid));

    wgd_tstate_t *state = tunnelGetState(t);
    if (wid == 0)
    {
        wireguarddeviceStateLock(state);
        wtimer_t *timer             = state->wg_device.loop_timer;
        state->wg_device.loop_timer = NULL;
        wireguarddeviceStateUnlock(state);

        if (timer != NULL)
        {
            weventSetUserData(timer, NULL);
            wtimerDelete(timer);
        }
    }
}

void wireguarddeviceTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadIsEventWorkerWID(wid));
    wireguarddeviceCloseTransportLine(t, wid);
}
