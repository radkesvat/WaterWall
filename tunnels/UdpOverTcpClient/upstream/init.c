#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    udpovertcpclient_lstate_t *ls = lineGetState(l, t);

    udpovertcpclientLinestateInitialize(ls, lineGetBufferPool(l));
    if (UNLIKELY(ls->read_stream == NULL))
    {
        udpovertcpclientLinestateDestroy(ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    tunnelNextUpStreamInit(t, l);
}
