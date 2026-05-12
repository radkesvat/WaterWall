#include "structure.h"

#include "loggers/network_logger.h"

void ptcTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    ptc_lstate_t *ls = lineGetState(l, t);

    if (! ls->read_paused)
    {
        return;
    }

    ls->read_paused = false;

    if (ls->kind != kPtcLineKindTcp || ls->read_paused_len == 0)
    {
        return;
    }

    LOCK_TCPIP_CORE();
    if (ls->tcp_pcb != NULL)
    {
        tcp_recved(ls->tcp_pcb, ls->read_paused_len);
        ls->read_paused_len = 0;
        tcp_output(ls->tcp_pcb);
    }
    UNLOCK_TCPIP_CORE();
}
