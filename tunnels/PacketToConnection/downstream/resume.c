#include "structure.h"

#include "loggers/network_logger.h"

void ptcTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    ptc_lstate_t *lstate      = lineGetState(l, t);
    bool          unlock_core = false;
    if (! lstate->stack_owned_locked && ! lstate->local_locked)
    {
        // we are on a different worker thread, so we must lock the tcpip mutex
        LOCK_TCPIP_CORE();
        assert(lineIsAlive(l));

        unlock_core = true;
    }

    if (lstate->read_paused && ! lstate->is_closing)
    {
        lstate->read_paused = false;
        if (lstate->is_tcp && lstate->read_paused_len > 0)
        {
            tcp_recved(lstate->tcp_pcb, lstate->read_paused_len);
            lstate->read_paused_len = 0;
        }
    }

    if (unlock_core)
    {
        UNLOCK_TCPIP_CORE();
    }
}
