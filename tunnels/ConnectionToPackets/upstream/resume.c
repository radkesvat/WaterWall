#include "structure.h"

#include "loggers/network_logger.h"

void ctpTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    if (UNLIKELY(ctpLineIsPacketLine(t, l)))
    {
        LOGF("ConnectionToPackets: unexpected upstream Resume on the packet line");
        abortProgramNow(1);
        return;
    }

    ctp_lstate_t *ls = lineGetState(l, t);

    if (ls->tunnel == NULL || ! ls->read_paused)
    {
        return;
    }

    ls->read_paused = false;

    if (ls->kind != (uint8_t) kCtpLineKindTcp || ls->read_paused_len == 0)
    {
        return;
    }

    // Return the complete paused subset in one window update, then decrement
    // the total outstanding credit without artificial 16-bit chunks.
    ww_lwip_engine_t *previous;
    const bool        entered = wwLwipEngineEnter(ls->engine, &previous);
    assert(entered);
    discard entered;
    if (ls->tcp_pcb != NULL)
    {
        ctpTcpReturnReceiveCreditLocked(ls, ls->read_paused_len);
        tcp_output(ls->tcp_pcb);
    }
    ls->read_paused_len = 0;
    wwLwipEngineLeave(ls->engine, previous);
    ctpDrainTerminalLinesOnCurrentWorker(t, lineGetWID(l));
}
