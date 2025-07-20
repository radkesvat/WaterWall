#include "structure.h"

#include "loggers/network_logger.h"

void reverseclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    reverseclient_lstate_t *dls = lineGetState(l, t);

    tunnelNextUpStreamPayload(t, dls->u, buf);
}
