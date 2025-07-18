#include "structure.h"

#include "loggers/network_logger.h"

void udplistenerTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    udplistener_lstate_t *lstate = lineGetState(l, t);

    bool deleted =
        idleTableRemoveIdleItemByHash(lstate->idle_handle->wid, lstate->uio->table, lstate->idle_handle->hash);
    if (! deleted)
    {
        LOGE("UdpListener: Failed to remove idle item for UDP listener on FD:%x", wioGetFD(lstate->uio->io));
        terminateProgram(1);
    }
    LOGD("UdpListener: Finished down stream for 1 connection on FD:%x", wioGetFD(lstate->uio->io));

    udplistenerLinestateDestroy(lstate);
    lineDestroy(l);
}
