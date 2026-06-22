#include "structure.h"

#include "loggers/network_logger.h"

void junkdatagramsenderTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    junkdatagramsender_lstate_t *ls = lineGetState(l, t);
    junkdatagramsenderLinestateDestroy(ls);

    tunnelNextUpStreamFinish(t, l);
}
