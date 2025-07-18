#include "structure.h"

#include "loggers/network_logger.h"

void udplistenerTunnelDownStreamInit(tunnel_t *t, line_t *l)
{

    discard t;
    discard l;
    LOGF("UdpListener: DownStream Init is disabled");
    terminateProgram(1);
}
