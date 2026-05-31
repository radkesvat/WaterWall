#include "structure.h"

#include "loggers/network_logger.h"

void headerclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    headerclient_lstate_t *ls = lineGetState(l, t);
    headerclientLinestateDestroy(ls);

    tunnelPrevDownStreamFinish(t, l);
}
