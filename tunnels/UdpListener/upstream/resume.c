#include "structure.h"

#include "loggers/network_logger.h"

void udplistenerTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("UdpListener: upStreamResume disabled");
    terminateProgram(1);
}
