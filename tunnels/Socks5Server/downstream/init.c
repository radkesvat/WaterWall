#include "structure.h"

#include "loggers/network_logger.h"

void socks5serverTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    socks5serverRequireCurrentLineWorker(l, "downstream Init");
    discard t;
}
