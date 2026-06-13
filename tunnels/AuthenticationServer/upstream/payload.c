#include "structure.h"

#include "loggers/network_logger.h"

void authenticationserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    authenticationserver_lstate_t *ls = lineGetState(l, t);

    if (ts->verbose)
    {
        LOGD("AuthenticationServer: upstream payload bytes=%u", (unsigned int) sbufGetLength(buf));
    }

    bufferstreamPush(&ls->read_stream, buf);
    discard authenticationserverProcessRequests(t, l, ls);
}
