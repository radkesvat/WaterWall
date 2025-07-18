#include "structure.h"

#include "loggers/network_logger.h"

void udplistenerTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("UdpListener: upStreamEst disabled");
    terminateProgram(1);
    
}
