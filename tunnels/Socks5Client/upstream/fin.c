#include "structure.h"

#include "loggers/network_logger.h"

void socks5clientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    socks5clientLinestateDestroy(lineGetState(l, t));
    tunnelNextUpStreamFinish(t, l);
}
