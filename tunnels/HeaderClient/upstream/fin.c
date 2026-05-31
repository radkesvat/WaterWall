#include "structure.h"

#include "loggers/network_logger.h"

void headerclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    headerclient_lstate_t *ls = lineGetState(l, t);
    headerclientLinestateDestroy(ls);

    tunnelNextUpStreamFinish(t, l);
}
