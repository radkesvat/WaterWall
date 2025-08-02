#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    udpovertcpclient_lstate_t *ls = lineGetState(l, t);
    udpovertcpclientLinestateDestroy(ls);

    tunnelNextUpStreamFinish(t, l);
}
