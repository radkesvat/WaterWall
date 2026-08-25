#include "structure.h"

#include "loggers/network_logger.h"

void streamtopacketsTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    streamtopackets_lstate_t *line_ls = lineGetState(l, t);

    streamtopacketsLinestateInitialize(line_ls, lineGetBufferPool(l));

    /*
     * Registration alone neither changes the active source nor makes this line
     * selectable: it stays a candidate until it produces a valid IPv4 packet or a
     * valid sensitive-mode heartbeat.
     */
    if (UNLIKELY(! streamtopacketsRegisterCandidateLine(t, l)))
    {
        // An untracked line could never be authorized, so close it rather than
        // keep a connection that can only ever drop traffic. The line is
        // borrowed, so its owner performs the destruction.
        streamtopacketsLinestateDestroy(line_ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    discard lineCallWithRef(l, tunnelPrevDownStreamEst, t);
}
