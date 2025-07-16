#include "structure.h"

#include "loggers/network_logger.h"

void packetasdataTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{

    discard t;
    discard l;

    LOGW("PacketAsData: not supposed to receive upstream fin");
}
