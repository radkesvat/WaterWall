#include "structure.h"

#include "loggers/network_logger.h"

void authenticationclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    authenticationclient_lstate_t *ls = lineGetState(l, t);

    lineLock(l);
    bufferstreamPush(&ls->read_stream, buf);
    discard authenticationclientProcessResponses(t, l, ls);
    lineUnlock(l);
}
