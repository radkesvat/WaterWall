#include "structure.h"

#include "loggers/network_logger.h"

void udplistenerTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("UdpListener: upStreamPause disabled");
    terminateProgram(1);

}
