#include "structure.h"

#include "loggers/network_logger.h"

void udplistenerTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("UdpListener: upStreamInit disabled");
    terminateProgram(1);
}
