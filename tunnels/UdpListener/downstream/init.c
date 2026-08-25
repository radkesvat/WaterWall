#include "structure.h"

#include "loggers/network_logger.h"

void udplistenerTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    udplistenerRequireCurrentLineWorker(l, "downstream Init");
    discard t;
    LOGF("UdpListener: DownStream Init is disabled");
    abortProgramNow(1);
}
