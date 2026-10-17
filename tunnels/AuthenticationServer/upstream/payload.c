#include "structure.h"

#include "../../Internals/AuthenticationCommon/stream.h"

#include "loggers/network_logger.h"

void authenticationserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    authenticationserver_lstate_t *ls = lineGetState(l, t);

    const uint32_t max_message =
        kAuthenticationServerMaxMessagePayload + kAuthenticationServerRequestEnvelopeHeaderSize;
    if (sbufGetLength(buf) == 0)
    {
        lineReuseBuffer(l, buf);
        return;
    }
    if (ls->processing_requests)
    {
        if (! authenticationStreamPushNested(&ls->read_stream, buf, max_message))
        {
            lineReuseBuffer(l, buf);
            authenticationserverCloseLine(t, l, ls, "request storage limit");
        }
        return;
    }

    if (ts->verbose)
    {
        LOGD("AuthenticationServer: upstream payload bytes=%u", (unsigned int) sbufGetLength(buf));
    }

    lineRef(l);
    bufferstreamPush(&ls->read_stream, buf);
    if (authenticationserverProcessRequests(t, l, ls))
        authenticationStreamCompactIncomplete(&ls->read_stream, max_message);
    lineUnref(l);
}
