#include "structure.h"

#include "loggers/network_logger.h"

void bgp4clientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    bgp4client_lstate_t *ls = lineGetState(l, t);
    bgp4clientLinestateDestroy(ls);

    tunnelNextUpStreamFinish(t, l);
}
