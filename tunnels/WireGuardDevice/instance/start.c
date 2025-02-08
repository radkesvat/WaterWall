#include "structure.h"

#include "loggers/network_logger.h"

static void loopHandle(wtimer_t *timer)
{
    wgd_tstate_t *state  = weventGetUserdata(timer);
    wireguarddeviceLoop((wireguard_device_t*)state);
}

void wireguarddeviceTunnelOnStart(tunnel_t *t)
{
    wgd_tstate_t *state = tunnelGetState(t);

    // Start a periodic timer for this wireguard device
    state->wg_device.loop_timer = wtimerAdd(getWorkerLoop(0), loopHandle, WIREGUARDIF_TIMER_MSECS, INFINITE),

    weventSetUserData(state->wg_device.loop_timer, state);

    (void) t;
}
