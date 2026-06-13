#include "structure.h"

#include "loggers/network_logger.h"

void packetsenderTunnelOnStop(tunnel_t *t)
{
    discard t;
}

void packetsenderTunnelOnWorkerStop(tunnel_t *t, wid_t wid)
{
    assert(wid == getWID());

    packetsender_tstate_t *state = tunnelGetState(t);
    if (state->workers == NULL || wid >= state->workers_count)
    {
        return;
    }

    packetsender_worker_state_t *slot = &state->workers[wid];
    if (slot->timer == NULL)
    {
        return;
    }

    weventSetUserData(slot->timer, NULL);
    wtimerDelete(slot->timer);
    slot->timer = NULL;
}
