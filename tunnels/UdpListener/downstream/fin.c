#include "structure.h"

#include "loggers/network_logger.h"

void udplistenerTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    udplistener_lstate_t *lstate = lineGetState(l, t);
    idle_item_t          *idle   = lstate->idle_handle;

    if (idle == NULL)
    {
        LOGE("UdpListener: downstream finish received before idle item was attached");
        udplistenerLinestateDestroy(lstate);
        lineDestroy(l);
        return;
    }

    bool deleted = idletableRemoveIdleItemByHash(idle->wid, lstate->uio->table, idle->hash);
    if (! deleted)
    {
        LOGE("UdpListener: Failed to remove idle item for UDP listener on FD:%x", wioGetFD(lstate->uio->io));
        terminateProgram(1);
    }
    LOGD("UdpListener: Finished down stream for 1 connection on FD:%x", wioGetFD(lstate->uio->io));

    lstate->idle_handle = NULL;
    udplistenerLinestateDestroy(lstate);
    lineDestroy(l);
}
