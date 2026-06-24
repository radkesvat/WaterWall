#include "structure.h"

#include "loggers/network_logger.h"

void wireguarddeviceTunnelOnStop(tunnel_t *t)
{
    discard t;
}

void wireguarddeviceTunnelOnWorkerStop(tunnel_t *t, wid_t wid)
{
    assert(wid == getWID());

    if (wid != 0)
    {
        wireguarddeviceCloseTransportLine(t, wid);
        return;
    }

    wgd_tstate_t *state = tunnelGetState(t);

    wireguarddeviceStateLock(state);
    wtimer_t *timer             = state->wg_device.loop_timer;
    state->wg_device.loop_timer = NULL;
    wireguarddeviceStateUnlock(state);

    if (timer == NULL)
    {
        wireguarddeviceCloseTransportLine(t, wid);
        return;
    }

    weventSetUserData(timer, NULL);
    wtimerDelete(timer);
    wireguarddeviceCloseTransportLine(t, wid);
}
