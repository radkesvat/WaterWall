#include "structure.h"

#include "loggers/network_logger.h"

void ptcTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    ptc_lstate_t *lstate = lineGetState(l, t);

    // we are on a different worker thread, so we must lock the tcpip mutex
    LOCK_TCPIP_CORE();

    if (lstate->read_paused && lstate->tcp_pcb != NULL)
    {
        lstate->read_paused = false;
        if (lstate->is_tcp && lstate->read_paused_len > 0)
        {
            tcp_recved(lstate->tcp_pcb, lstate->read_paused_len);
            lstate->read_paused_len = 0;
            tcp_output(lstate->tcp_pcb);
        }
    }

    UNLOCK_TCPIP_CORE();
}
