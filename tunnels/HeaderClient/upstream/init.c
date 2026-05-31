#include "structure.h"

#include "loggers/network_logger.h"

void headerclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    headerclient_lstate_t *ls = lineGetState(l, t);
    headerclientLinestateInitialize(ls);

    tunnelNextUpStreamInit(t, l);
}
