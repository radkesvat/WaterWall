#include "structure.h"

#include "loggers/network_logger.h"

void ctpTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    if (UNLIKELY(ctpLineIsPacketLine(t, l)))
    {
        LOGF("ConnectionToPackets: unexpected upstream Pause on the packet line");
        abortProgramNow(1);
        return;
    }

    ctp_lstate_t *ls = lineGetState(l, t);

    if (ls->tunnel == NULL)
    {
        return;
    }

    // prev cannot accept downstream payload right now. TCP stops returning
    // receive credit so the window closes; UDP starts dropping.
    ls->read_paused = true;
}
