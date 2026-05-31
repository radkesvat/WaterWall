#include "structure.h"

#include "loggers/network_logger.h"

void bgp4serverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    bgp4server_lstate_t *ls = lineGetState(l, t);
    bgp4serverLinestateDestroy(ls);

    tunnelNextUpStreamFinish(t, l);
}
