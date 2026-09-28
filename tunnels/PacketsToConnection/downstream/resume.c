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

    ww_lwip_engine_t *previous;
    const bool        entered = wwLwipEngineEnter(ls->engine, &previous);
    assert(entered);
    discard        entered;
    const uint32_t paused = ls->read_paused_len;
    if (ptcReturnReceiveCreditLocked(ls, paused))
    {
        ls->read_paused_len = 0;
        tcp_output(ls->tcp_pcb);
    }
    wwLwipEngineLeave(ls->engine, previous);
}
