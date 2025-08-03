#include "structure.h"

#include "loggers/network_logger.h"

void udplistenerTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    udplistener_lstate_t *ls = lineGetState(l, t);

    idletableKeepIdleItemForAtleast(ls->uio->table, ls->idle_handle, (uint64_t) kUdpKeepExpireTime);

    postUdpWrite(ls->uio, lineGetWID(l), buf);

}
