#include "loggers/network_logger.h"
#include "structure.h"


void tcplistenerTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    tcplistener_lstate_t *lstate = lineGetState(l, t);

    // This indicates that line is closed. Even if we get the closeCallback
    // while flushing the queue, no FIN will be sent to upstream
    weventSetUserData(lstate->io, NULL);

    tcplistenerFlushWriteQueue(lstate);

    tcplistenerLinestateDestroy(lstate);
    lineDestroy(l);
}
