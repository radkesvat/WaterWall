#include "structure.h"

#include "loggers/network_logger.h"

void udpconnectorTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{

    udpconnector_lstate_t *ls = lineGetState(l, t);
    wio_t                 *io = ls->io;
    weventSetUserData(io, NULL);
    udpconnectorLinestateDestroy(ls);
    wioClose(io);
}
