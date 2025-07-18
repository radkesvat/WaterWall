#include "structure.h"

#include "loggers/network_logger.h"

void udplistenerTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    udplistener_lstate_t *ls = lineGetState(l, t);
    postUdpWrite(ls->uio, lineGetWID(l), buf);

}
