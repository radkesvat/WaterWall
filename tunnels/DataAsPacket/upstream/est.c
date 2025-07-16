#include "structure.h"

#include "loggers/network_logger.h"

void dataaspacketTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;

    LOGW("DataAsPacket: not supposed to receive upstream Est");
}
