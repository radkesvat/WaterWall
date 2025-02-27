#include "structure.h"

#include "loggers/network_logger.h"

void ptcTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    ptc_lstate_t *lstate = lineGetState(l, t);
    bool unlock_core = false;
    if (! lstate->stack_owned_locked && ! lstate->local_locked)
    {
        // we are on a different worker thread, so we must lock the tcpip mutex
        LOCK_TCPIP_CORE();
        assert(lineIsAlive(l));

        unlock_core = true;
    }

    if (! lstate->read_paused)
    {
        lstate->read_paused = true;
    }

    if (unlock_core)
    {
        UNLOCK_TCPIP_CORE();
    }
}
