#include "structure.h"

#include "loggers/network_logger.h"

void authenticationserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    authenticationserver_lstate_t *ls = lineGetState(l, t);

    bufferstreamPush(&ls->read_stream, buf);
    discard authenticationserverProcessRequests(t, l, ls);
}
