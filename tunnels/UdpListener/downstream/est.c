#include "structure.h"

#include "loggers/network_logger.h"

void udplistenerTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    udplistenerRequireCurrentLineWorker(l, "downstream Est");
    discard t;
    lineMarkEstablished(l);
}
