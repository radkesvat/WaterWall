#include "structure.h"

#include "loggers/network_logger.h"

void streamtopacketsTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    streamtopackets_lstate_t *line_ls = lineGetState(l, t);

    /*
     * The previous side is the sender here, so nothing is sent back toward it and
     * nothing is sent toward the packet side. This borrowed line is only removed
     * from the registry - if it was the last active line of the current source
     * generation, the registry clears the active owner and stales queued writes.
     */
    streamtopacketsUnregisterLine(t, l);
    streamtopacketsLinestateDestroy(line_ls);
}
