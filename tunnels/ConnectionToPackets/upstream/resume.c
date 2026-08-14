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

    // Release exactly the paused subset. The helper chunks windows larger than
    // one tcp_recved() argument and decrements the total outstanding credit.
    LOCK_TCPIP_CORE();
    if (ls->tcp_pcb != NULL)
    {
        ctpTcpReturnReceiveCreditLocked(ls, ls->read_paused_len);
        tcp_output(ls->tcp_pcb);
    }
    ls->read_paused_len = 0;
    UNLOCK_TCPIP_CORE();
    ctpDrainTerminalLinesOnCurrentWorker(t, lineGetWID(l));
}
