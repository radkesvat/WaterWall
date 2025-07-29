#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{

    tlsclient_lstate_t *ls = lineGetState(l, t);

    tlsclientLinestateDestroy(ls);

    tunnelNextUpStreamFinish(t, l);
}
