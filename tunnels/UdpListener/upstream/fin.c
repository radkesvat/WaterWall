#include "structure.h"

#include "loggers/network_logger.h"

void udplistenerTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{

    discard t;
    discard l;
    LOGF("UdpListener: upStreamFinish disabled");
    terminateProgram(1);
}
