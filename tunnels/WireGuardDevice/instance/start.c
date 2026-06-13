#include "structure.h"

#include "loggers/network_logger.h"

static void loopHandle(wtimer_t *timer)
{
    wgd_tstate_t *state = weventGetUserdata(timer);
    if (state == NULL)
    {
        return;
    }

    wireguarddeviceStateLock(state);
    const bool active = state->wg_device.loop_timer == timer && ! isApplicationTerminating();
    wireguarddeviceStateUnlock(state);

    if (! active)
    {
        return;
    }

    wireguarddeviceLoop((wireguard_device_t *) state);
}

void wireguarddeviceTunnelOnStart(tunnel_t *t)
{
    wgd_tstate_t *state = tunnelGetState(t);

    wireguard_device_t *device = (wireguard_device_t *) state;
    for (uint8_t i = 0; i < WIREGUARD_MAX_PEERS; i++)
    {
        wireguard_peer_t *peer = &device->peers[i];
        if (peer->valid)
        {
            if (wireguardifConnect(device, i) != ERR_OK)
            {
                LOGF("Error: wireguardifConnect failed");
                terminateProgram(1);
            }
        }
    }

    state->wg_device.loop_timer = wtimerAdd(getWorkerLoop(0), loopHandle, WIREGUARDIF_TIMER_MSECS, INFINITE);
    if (state->wg_device.loop_timer == NULL)
    {
        LOGF("WireGuardDevice: failed to create periodic timer");
        terminateProgram(1);
    }
    weventSetUserData(state->wg_device.loop_timer, state);

    discard t;
}
